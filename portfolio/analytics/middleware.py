import hashlib
import hmac
import logging
import re
import secrets
import time
from datetime import timedelta

from django.conf import settings
from django.core.cache import caches
from django.db import DatabaseError, transaction
from django.utils import timezone

from .detection import assess_request, classify_user_agent, request_ip, request_location
from .models import PageView, SecurityEvent, Visitor


logger = logging.getLogger(__name__)
COOKIE_NAME = "visitor_id"
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{24,80}$")


def analytics_cache():
    return caches["analytics"]


class VisitTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not self._should_track(request):
            return self.get_response(request)

        started = time.monotonic()
        token, set_cookie = self._visitor_token(request)
        ip = request_ip(request)
        rate = self._rate(ip)
        assessment = assess_request(request, rate)
        response = self.get_response(request)
        response_ms = max(0, round((time.monotonic() - started) * 1000))

        # A failed/scanner-style response is more suspicious than the request
        # alone, but ordinary 404s are not treated as attacks.
        if response.status_code >= 400 and assessment["scanner"]:
            assessment["risk_score"] = min(100, assessment["risk_score"] + 15)
        threshold = getattr(settings, "ANALYTICS_RATE_LIMIT_PER_MINUTE", 60)
        multiplier = max(1, getattr(settings, "ANALYTICS_ATTACK_SAMPLE_MULTIPLIER", 3))
        should_sample = rate > threshold * multiplier and rate % 10 != 0
        try:
            if not should_sample:
                self._record(
                    request, response, response_ms, token, ip, rate, assessment
                )
        except (DatabaseError, ValueError, TypeError):
            # Analytics must never make the public website unavailable.
            logger.exception("Traffic event could not be recorded")
        if set_cookie:
            response.set_cookie(
                COOKIE_NAME,
                token,
                max_age=365 * 24 * 60 * 60,
                httponly=True,
                secure=not settings.DEBUG,
                samesite="Lax",
            )
        return response

    @staticmethod
    def _should_track(request):
        if not getattr(settings, "ANALYTICS_ENABLED", True):
            return False
        if request.method not in ("GET", "HEAD", "POST", "OPTIONS"):
            return True
        excluded = getattr(settings, "ANALYTICS_EXCLUDED_PATHS", ())
        if any(request.path.startswith(prefix) for prefix in excluded):
            return False
        user = getattr(request, "user", None)
        return not (user and user.is_authenticated and user.is_staff)

    @staticmethod
    def _visitor_token(request):
        token = request.COOKIES.get(COOKIE_NAME, "")
        if TOKEN_PATTERN.fullmatch(token):
            return token, False
        return secrets.token_urlsafe(32), True

    @staticmethod
    def _token_hash(token):
        secret = str(settings.SECRET_KEY).encode("utf-8")
        return hmac.new(secret, token.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _rate(ip):
        if not ip:
            return 1
        bucket = int(time.time() // 60)
        key_hash = hashlib.sha256(ip.encode("utf-8")).hexdigest()[:20]
        key = f"analytics-rate:{key_hash}:{bucket}"
        try:
            shared_cache = analytics_cache()
            if shared_cache.add(key, 1, timeout=75):
                return 1
            return shared_cache.incr(key)
        except Exception:
            logger.warning("Shared analytics rate cache is unavailable")
            return 1

    @transaction.atomic
    def _record(self, request, response, response_ms, token, ip, rate, assessment):
        now = timezone.now()
        country, city = request_location(request)
        token_hash = self._token_hash(token)
        visitor, created = Visitor.objects.get_or_create(
            token_hash=token_hash,
            defaults={
                "last_seen": now,
                "first_ip": ip,
                "last_ip": ip,
                "last_user_agent": assessment["user_agent"],
                "last_country": country,
                "last_city": city,
                "pageview_count": 0,
                "is_known_bot": assessment["is_bot"],
                "max_risk_score": assessment["risk_score"],
            },
        )
        if not created:
            if now - visitor.last_seen > timedelta(minutes=30):
                visitor.session_count += 1
            visitor.last_seen = now
            visitor.last_ip = ip
            visitor.last_user_agent = assessment["user_agent"]
            visitor.last_country = country
            visitor.last_city = city
            visitor.is_known_bot = visitor.is_known_bot or assessment["is_bot"]
            visitor.max_risk_score = max(
                visitor.max_risk_score, assessment["risk_score"]
            )
        visitor.pageview_count += 1
        visitor.save()

        device, browser = classify_user_agent(assessment["user_agent"])
        pageview = PageView.objects.create(
            visitor=visitor,
            method=request.method,
            path=request.path[:1000],
            status_code=response.status_code,
            response_ms=response_ms,
            ip_address=ip,
            country=country,
            city=city,
            user_agent=assessment["user_agent"],
            referrer=request.META.get("HTTP_REFERER", "")[:2000],
            device_type=device,
            browser=browser,
            is_bot=assessment["is_bot"],
            bot_reason=assessment["reason"],
            risk_score=assessment["risk_score"],
            requests_per_minute=rate,
        )
        if assessment["risk_score"] >= 40:
            if rate > getattr(settings, "ANALYTICS_RATE_LIMIT_PER_MINUTE", 60):
                event_type = "rate_spike"
                summary = f"High request rate detected ({rate}/min)"
            elif assessment["scanner"]:
                event_type = "scanner"
                summary = "Request matched a common vulnerability scan"
            elif assessment["is_bot"]:
                event_type = "automation"
                summary = "Suspicious automated client detected"
            else:
                event_type = "bad_request"
                summary = "Request matched multiple risk signals"
            # One alert per IP/type/minute keeps a burst from flooding the
            # investigation queue. Individual sampled requests remain visible.
            alert_source = f"{ip or 'unknown'}:{event_type}"
            alert_hash = hashlib.sha256(alert_source.encode("utf-8")).hexdigest()[:20]
            alert_key = f"analytics-alert:{alert_hash}:{int(time.time() // 60)}"
            try:
                first_alert = analytics_cache().add(alert_key, 1, timeout=75)
            except Exception:
                logger.warning("Shared analytics alert cache is unavailable")
                first_alert = True
            if not first_alert:
                return
            score = assessment["risk_score"]
            severity = "critical" if score >= 80 else "high" if score >= 60 else "medium"
            SecurityEvent.objects.create(
                visitor=visitor,
                pageview=pageview,
                event_type=event_type,
                severity=severity,
                ip_address=ip,
                path=request.path[:1000],
                summary=summary,
                evidence={
                    "risk_score": score,
                    "signals": assessment["reason"],
                    "requests_per_minute": rate,
                    "status_code": response.status_code,
                    "method": request.method,
                },
            )
