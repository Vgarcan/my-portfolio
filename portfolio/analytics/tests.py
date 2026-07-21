import json
from datetime import timedelta
from io import StringIO

from bs4 import BeautifulSoup
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .models import PageView, SecurityEvent, Visitor
from .geo import country_map_position


HUMAN_HEADERS = {
    "HTTP_USER_AGENT": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
    ),
    "HTTP_ACCEPT": "text/html,application/xhtml+xml",
}

TEST_CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "tests-default",
    },
    "analytics": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "tests-analytics",
    },
}


class CompatibleClient(Client):
    """Client without template-context copying, broken in Django 5.1/Python 3.14."""

    def request(self, **request):
        response = self.handler(self._base_environ(**request))
        self.check_exception(response)
        response.client = self
        response.request = request
        self.cookies.update(response.cookies)
        return response


class CompatibleTestCase(TestCase):
    client_class = CompatibleClient


@override_settings(CACHES=TEST_CACHES)
class TrackingMiddlewareTests(CompatibleTestCase):
    def test_country_coordinates_cover_known_iso_codes(self):
        for code in ("GB", "US", "SG", "ES"):
            x, y = country_map_position(code)
            self.assertGreater(x, 0)
            self.assertLess(x, 100)
            self.assertGreater(y, 0)
            self.assertLess(y, 100)

    def test_public_requests_create_a_recurring_pseudonymous_visitor(self):
        first = self.client.get("/", **HUMAN_HEADERS)
        self.assertEqual(first.status_code, 200)
        self.assertIn("visitor_id", first.cookies)
        self.client.get("/", **HUMAN_HEADERS)

        self.assertEqual(Visitor.objects.count(), 1)
        visitor = Visitor.objects.get()
        self.assertEqual(visitor.pageview_count, 2)
        self.assertTrue(visitor.is_returning)
        self.assertEqual(PageView.objects.filter(visitor=visitor).count(), 2)
        self.assertNotEqual(visitor.token_hash, first.cookies["visitor_id"].value)

    @override_settings(ANALYTICS_TRUSTED_PROXIES=[])
    def test_forwarded_ip_and_location_are_ignored_from_untrusted_clients(self):
        self.client.get(
            "/",
            REMOTE_ADDR="203.0.113.9",
            HTTP_X_FORWARDED_FOR="1.1.1.1",
            HTTP_CF_IPCOUNTRY="ZZ",
            **HUMAN_HEADERS,
        )
        pageview = PageView.objects.get()
        self.assertEqual(pageview.ip_address, "203.0.113.9")
        self.assertEqual(pageview.country, "")

    @override_settings(ANALYTICS_TRUSTED_PROXIES=["127.0.0.1"])
    def test_trusted_proxy_can_supply_ip_and_country(self):
        self.client.get(
            "/",
            REMOTE_ADDR="127.0.0.1",
            HTTP_CF_CONNECTING_IP="198.51.100.22",
            HTTP_CF_IPCOUNTRY="ES",
            HTTP_CF_IPCITY="Madrid",
            **HUMAN_HEADERS,
        )
        pageview = PageView.objects.get()
        self.assertEqual(pageview.ip_address, "198.51.100.22")
        self.assertEqual(pageview.country, "ES")
        self.assertEqual(pageview.city, "Madrid")

    def test_scanner_request_generates_a_high_risk_security_event(self):
        response = self.client.get(
            "/.env", REMOTE_ADDR="198.51.100.30",
            HTTP_USER_AGENT="curl/8.0", HTTP_ACCEPT="*/*"
        )
        self.assertEqual(response.status_code, 404)
        pageview = PageView.objects.get()
        event = SecurityEvent.objects.get()
        self.assertTrue(pageview.is_bot)
        self.assertGreaterEqual(pageview.risk_score, 80)
        self.assertEqual(event.event_type, "scanner")
        self.assertEqual(event.severity, "critical")

    def test_ai_crawler_is_classified_as_bot_without_a_security_alert(self):
        self.client.get(
            "/robots.txt", REMOTE_ADDR="198.51.100.35",
            HTTP_USER_AGENT=(
                "Mozilla/5.0 AppleWebKit/537.36 compatible; ClaudeBot/1.0"
            ),
            HTTP_ACCEPT="text/plain",
        )
        pageview = PageView.objects.get()
        self.assertTrue(pageview.is_bot)
        self.assertEqual(pageview.device_type, "Bot")
        self.assertLess(pageview.risk_score, 40)
        self.assertFalse(SecurityEvent.objects.exists())

    def test_repeated_scans_are_grouped_into_one_alert_per_minute(self):
        headers = {
            "REMOTE_ADDR": "198.51.100.40",
            "HTTP_USER_AGENT": "curl/8.0",
            "HTTP_ACCEPT": "*/*",
        }
        self.client.get("/.env", **headers)
        self.client.get("/wp-admin/", **headers)
        self.assertEqual(PageView.objects.count(), 2)
        self.assertEqual(SecurityEvent.objects.count(), 1)

    @override_settings(
        ANALYTICS_RATE_LIMIT_PER_MINUTE=2,
        ANALYTICS_ATTACK_SAMPLE_MULTIPLIER=1,
    )
    def test_extreme_bursts_are_sampled_to_protect_the_database(self):
        headers = {**HUMAN_HEADERS, "REMOTE_ADDR": "198.51.100.41"}
        for _ in range(10):
            self.client.get("/", **headers)
        self.assertEqual(PageView.objects.count(), 3)
        self.assertEqual(PageView.objects.order_by("occurred_at").last().requests_per_minute, 10)

    @override_settings(ANALYTICS_ENABLED=False)
    def test_tracking_can_be_disabled(self):
        self.client.get("/", **HUMAN_HEADERS)
        self.assertFalse(PageView.objects.exists())


@override_settings(CACHES=TEST_CACHES)
class DashboardAccessTests(CompatibleTestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="operator", password="safe-test-password", is_staff=True
        )

    def test_anonymous_user_is_redirected_to_admin_login(self):
        response = self.client.get(reverse("analytics:dashboard"))
        self.assertRedirects(
            response,
            f"{reverse('admin:login')}?next={reverse('analytics:dashboard')}",
            fetch_redirect_response=False,
        )

    def test_staff_can_view_dashboard_without_tracking_their_own_request(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("analytics:dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Actividad del sitio")
        self.assertFalse(PageView.objects.exists())

    def test_dashboard_nav_button_is_only_visible_to_staff(self):
        dashboard_url = reverse("analytics:dashboard")
        anonymous = self.client.get("/", **HUMAN_HEADERS)
        self.assertNotContains(anonymous, dashboard_url)

        self.client.force_login(self.user)
        staff = self.client.get("/", **HUMAN_HEADERS)
        self.assertContains(staff, dashboard_url)
        self.assertContains(staff, "Dashboard")

    def test_sidebar_sections_filter_data_and_mark_the_correct_tab(self):
        self.client.get(
            "/.env", REMOTE_ADDR="198.51.100.70",
            HTTP_USER_AGENT="curl/8", HTTP_ACCEPT="*/*",
        )
        self.client.force_login(self.user)

        cases = (
            ("all", "Resumen de tráfico", "Actividad del sitio"),
            ("threat", "Amenazas", "Actividad sospechosa"),
            ("bot", "Bots y crawlers", "Bots y crawlers"),
        )
        for traffic, expected_tab, expected_title in cases:
            response = self.client.get(
                reverse("analytics:dashboard"), {"traffic": traffic}
            )
            self.assertEqual(response.status_code, 200)
            soup = BeautifulSoup(response.content, "html.parser")
            active = soup.select_one(".sidebar .nav-link.active")
            self.assertIsNotNone(active)
            self.assertIn(expected_tab, active.get_text(" ", strip=True))
            self.assertEqual(soup.select_one("h1").get_text(strip=True), expected_title)

    def test_staff_can_export_filtered_data(self):
        self.client.get("/", **HUMAN_HEADERS)
        self.client.force_login(self.user)
        response = self.client.get(reverse("analytics:export_csv"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv; charset=utf-8")
        self.assertIn("request_id", response.content.decode("utf-8-sig"))

    def test_live_data_endpoint_is_private_and_returns_a_fresh_snapshot(self):
        endpoint = reverse("analytics:dashboard_data")
        anonymous = self.client.get(endpoint)
        self.assertEqual(anonymous.status_code, 302)

        self.client.force_login(self.user)
        response = self.client.get(endpoint, {"traffic": "bot"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store, private")
        payload = json.loads(response.content)
        self.assertIn('id="dashboard-live"', payload["html"])
        self.assertIn('data-live-key="geography"', payload["html"])
        self.assertIn("Bots y crawlers", payload["html"])
        self.assertIn("updated_at", payload)

    @override_settings(ANALYTICS_TRUSTED_PROXIES=["127.0.0.1"])
    def test_world_map_exposes_country_metrics_and_tooltip_content(self):
        self.client.get(
            "/", REMOTE_ADDR="127.0.0.1",
            HTTP_CF_CONNECTING_IP="198.51.100.80",
            HTTP_CF_IPCOUNTRY="ES",
            HTTP_CF_IPCITY="Madrid",
            **HUMAN_HEADERS,
        )
        self.client.force_login(self.user)
        response = self.client.get(reverse("analytics:dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Mapa mundial de actividad")
        soup = BeautifulSoup(response.content, "html.parser")
        locations = json.loads(soup.select_one("#traffic-map-data").string)
        self.assertEqual(locations[0]["country"], "ES")
        self.assertEqual(locations[0]["latitude"], 40.0)
        self.assertContains(response, "jsvectormap@1.7.0")
        self.assertContains(response, "Respuesta media")

    def test_staff_can_resolve_an_alert(self):
        self.client.get(
            "/.git/config", REMOTE_ADDR="198.51.100.31",
            HTTP_USER_AGENT="curl/8", HTTP_ACCEPT="*/*",
        )
        event = SecurityEvent.objects.get()
        self.client.force_login(self.user)
        response = self.client.post(reverse("analytics:resolve_event", args=[event.pk]))
        self.assertRedirects(response, reverse("analytics:dashboard"))
        event.refresh_from_db()
        self.assertTrue(event.resolved)
        self.assertEqual(event.resolved_by, self.user)


@override_settings(CACHES=TEST_CACHES)
class RetentionCommandTests(CompatibleTestCase):
    def test_dry_run_does_not_delete_data(self):
        self.client.get("/", **HUMAN_HEADERS)
        pageview = PageView.objects.get()
        PageView.objects.filter(pk=pageview.pk).update(
            occurred_at=timezone.now() - timedelta(days=100)
        )
        output = StringIO()
        call_command("purge_analytics", days=90, dry_run=True, stdout=output)
        self.assertTrue(PageView.objects.exists())
        self.assertIn("Would delete 1 page views", output.getvalue())
