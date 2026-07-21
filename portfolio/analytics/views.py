import csv
from collections import Counter
from datetime import timedelta

from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Avg, Count, Max, Q
from django.db.models.functions import TruncDate
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.utils import timezone
from django.views.decorators.http import require_POST

from .detection import referrer_host
from .geo import country_coordinates
from .models import PageView, SecurityEvent, Visitor


ALLOWED_PERIODS = {1, 7, 30, 90}


def _period(request):
    try:
        days = int(request.GET.get("days", 7))
    except (TypeError, ValueError):
        days = 7
    return days if days in ALLOWED_PERIODS else 7


def _filtered_pageviews(request):
    days = _period(request)
    start = timezone.now() - timedelta(days=days)
    qs = PageView.objects.select_related("visitor").filter(occurred_at__gte=start)
    traffic = request.GET.get("traffic", "all")
    if traffic == "human":
        qs = qs.filter(is_bot=False, risk_score__lt=60)
    elif traffic == "bot":
        qs = qs.filter(is_bot=True)
    elif traffic == "threat":
        qs = qs.filter(risk_score__gte=60)
    else:
        traffic = "all"

    status = request.GET.get("status", "all")
    if status == "success":
        qs = qs.filter(status_code__lt=400)
    elif status == "error":
        qs = qs.filter(status_code__gte=400)
    else:
        status = "all"

    query = request.GET.get("q", "").strip()[:120]
    if query:
        qs = qs.filter(
            Q(ip_address__icontains=query)
            | Q(path__icontains=query)
            | Q(city__icontains=query)
            | Q(country__icontains=query)
            | Q(visitor__token_hash__startswith=query)
            | Q(user_agent__icontains=query)
        )
    return qs, days, traffic, status, query


def _delta(current, previous):
    if not previous:
        return 100 if current else 0
    return round((current - previous) * 100 / previous)


def _dashboard_context(request):
    qs, days, traffic, status, query = _filtered_pageviews(request)
    now = timezone.now()
    start = now - timedelta(days=days)
    previous_start = start - timedelta(days=days)
    previous = PageView.objects.filter(
        occurred_at__gte=previous_start, occurred_at__lt=start
    )

    total = qs.count()
    unique = qs.values("visitor_id").distinct().count()
    returning = (
        qs.values("visitor_id")
        .annotate(period_views=Count("id"))
        .filter(period_views__gt=1)
        .count()
    )
    bots = qs.filter(is_bot=True).count()
    threats = qs.filter(risk_score__gte=60).count()
    errors = qs.filter(status_code__gte=400).count()
    avg_response = round(qs.aggregate(value=Avg("response_ms"))["value"] or 0)
    active_visitors = qs.filter(
        occurred_at__gte=now - timedelta(minutes=5)
    ).values("visitor_id").distinct().count()
    new_visitors = qs.filter(
        visitor__first_seen__gte=start
    ).values("visitor_id").distinct().count()
    slow_requests = qs.filter(response_ms__gte=1000).count()
    server_errors = qs.filter(status_code__gte=500).count()
    country_count = qs.exclude(country="").values("country").distinct().count()
    unique_pages = qs.values("path").distinct().count()

    previous_total = previous.count()
    previous_unique = previous.values("visitor_id").distinct().count()
    previous_threats = previous.filter(risk_score__gte=60).count()

    grouped_trend = {
        row["day"]: row
        for row in qs.annotate(day=TruncDate("occurred_at"))
        .values("day")
        .annotate(
            views=Count("id"),
            visitors=Count("visitor_id", distinct=True),
            threats=Count("id", filter=Q(risk_score__gte=60)),
        )
        .order_by("day")
    }
    trend = []
    for offset in range(days - 1, -1, -1):
        day = timezone.localdate() - timedelta(days=offset)
        row = grouped_trend.get(day, {})
        trend.append({
            "day": day,
            "label": day.strftime("%d %b"),
            "views": row.get("views", 0),
            "visitors": row.get("visitors", 0),
            "threats": row.get("threats", 0),
        })
    trend_max = max((row["views"] for row in trend), default=1) or 1
    for row in trend:
        row["height"] = max(3, round(row["views"] * 100 / trend_max)) if row["views"] else 2

    top_pages = list(
        qs.values("path")
        .annotate(
            views=Count("id"),
            visitors=Count("visitor_id", distinct=True),
            response=Avg("response_ms"),
        )
        .order_by("-views")[:8]
    )
    countries = list(
        qs.exclude(country="").values("country")
        .annotate(
            views=Count("id"),
            visitors=Count("visitor_id", distinct=True),
            bots=Count("id", filter=Q(is_bot=True)),
            threats=Count("id", filter=Q(risk_score__gte=60)),
            average_response=Avg("response_ms"),
            last_seen=Max("occurred_at"),
        )
        .order_by("-views")
    )
    map_locations = []
    for row in countries:
        coordinates = country_coordinates(row["country"])
        row["share"] = round(row["views"] * 100 / total) if total else 0
        row["bot_percent"] = round(row["bots"] * 100 / row["views"]) if row["views"] else 0
        row["average_response"] = round(row["average_response"] or 0)
        if coordinates:
            latitude, longitude = coordinates
            map_locations.append({
                "country": row["country"],
                "latitude": latitude,
                "longitude": longitude,
                "views": row["views"],
                "visitors": row["visitors"],
                "bot_percent": row["bot_percent"],
                "threats": row["threats"],
                "average_response": row["average_response"],
                "last_seen": row["last_seen"],
            })
    top_ips = list(
        qs.exclude(ip_address=None)
        .values("ip_address")
        .annotate(
            views=Count("id"),
            max_risk=Max("risk_score"),
            bots=Count("id", filter=Q(is_bot=True)),
        )
        .order_by("-views")[:8]
    )
    device_data = list(
        qs.values("device_type").annotate(total=Count("id")).order_by("-total")
    )
    browser_data = list(
        qs.values("browser").annotate(total=Count("id")).order_by("-total")[:6]
    )

    referrers = Counter(
        referrer_host(value)
        for value in qs.exclude(referrer="").values_list("referrer", flat=True)[:5000]
    )
    if total - sum(referrers.values()) > 0:
        referrers["Direct / unknown"] += total - sum(referrers.values())

    recent_views = qs.order_by("-occurred_at")[:50]
    filtered_events = SecurityEvent.objects.select_related(
        "visitor", "pageview"
    ).filter(pageview__in=qs, occurred_at__gte=start, resolved=False)
    recent_events = filtered_events[:12]

    section_copy = {
        "all": (
            "Actividad del sitio",
            "Visitantes, recurrencia y señales de seguridad en un solo lugar.",
        ),
        "threat": (
            "Actividad sospechosa",
            "Peticiones con riesgo alto, escáneres y posibles ataques.",
        ),
        "bot": (
            "Bots y crawlers",
            "Tráfico automatizado identificado por sus señales técnicas.",
        ),
        "human": (
            "Tráfico humano",
            "Actividad sin señales relevantes de automatización o riesgo.",
        ),
    }
    section_title, section_subtitle = section_copy[traffic]

    context = {
        "days": days,
        "traffic": traffic,
        "status": status,
        "query": query,
        "section_title": section_title,
        "section_subtitle": section_subtitle,
        "total": total,
        "unique": unique,
        "returning": returning,
        "bots": bots,
        "threats": threats,
        "errors": errors,
        "avg_response": avg_response,
        "active_visitors": active_visitors,
        "new_visitors": new_visitors,
        "slow_requests": slow_requests,
        "server_errors": server_errors,
        "country_count": country_count,
        "unique_pages": unique_pages,
        "geolocation_coverage": round(
            qs.exclude(country="").count() * 100 / total
        ) if total else 0,
        "total_delta": _delta(total, previous_total),
        "unique_delta": _delta(unique, previous_unique),
        "threat_delta": _delta(threats, previous_threats),
        "bot_percent": round(bots * 100 / total) if total else 0,
        "error_percent": round(errors * 100 / total) if total else 0,
        "returning_percent": round(returning * 100 / unique) if unique else 0,
        "trend": trend,
        "trend_peak": trend_max,
        "top_pages": top_pages,
        "countries": countries,
        "map_locations": map_locations,
        "top_ips": top_ips,
        "device_data": device_data,
        "browser_data": browser_data,
        "referrers": referrers.most_common(6),
        "recent_views": recent_views,
        "recent_events": recent_events,
        "open_event_count": filtered_events.count(),
        "last_updated": now,
    }
    return context


@staff_member_required(login_url="admin:login")
def dashboard(request):
    return render(
        request, "analytics/dashboard.html", _dashboard_context(request)
    )


@staff_member_required(login_url="admin:login")
def dashboard_data(request):
    """Return a fresh dashboard snapshot for the non-disruptive live refresh."""
    context = _dashboard_context(request)
    html = render_to_string(
        "analytics/dashboard.html", context=context, request=request
    )
    response = JsonResponse({
        "html": html,
        "updated_at": context["last_updated"].isoformat(),
    })
    response["Cache-Control"] = "no-store, private"
    return response


@staff_member_required(login_url="admin:login")
def visitor_detail(request, pk):
    visitor = get_object_or_404(Visitor, pk=pk)
    views = visitor.pageviews.all()[:200]
    stats = visitor.pageviews.aggregate(
        average_response=Avg("response_ms"),
        max_risk=Max("risk_score"),
        unique_pages=Count("path", distinct=True),
        unique_ips=Count("ip_address", distinct=True),
    )
    events = visitor.security_events.select_related("pageview")[:50]
    return render(request, "analytics/visitor_detail.html", {
        "visitor": visitor,
        "pageviews": views,
        "events": events,
        "stats": stats,
    })


@staff_member_required(login_url="admin:login")
def export_csv(request):
    qs, days, _traffic, _status, _query = _filtered_pageviews(request)
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="traffic-{days}d.csv"'
    response.write("\ufeff")
    writer = csv.writer(response)
    writer.writerow([
        "timestamp", "request_id", "visitor", "ip", "country", "city",
        "method", "path", "status", "response_ms", "device", "browser",
        "bot", "risk_score", "requests_per_minute", "referrer", "user_agent",
    ])
    for item in qs.order_by("-occurred_at").iterator(chunk_size=1000):
        writer.writerow([
            item.occurred_at.isoformat(), item.request_id,
            item.visitor.token_hash[:12], item.ip_address or "", item.country,
            item.city, item.method, item.path, item.status_code,
            item.response_ms, item.device_type, item.browser, item.is_bot,
            item.risk_score, item.requests_per_minute, item.referrer,
            item.user_agent,
        ])
    return response


@staff_member_required(login_url="admin:login")
@require_POST
def resolve_event(request, pk):
    event = get_object_or_404(SecurityEvent, pk=pk)
    event.resolved = not event.resolved
    event.resolved_at = timezone.now() if event.resolved else None
    event.resolved_by = request.user if event.resolved else None
    event.save(update_fields=("resolved", "resolved_at", "resolved_by"))
    return redirect(request.POST.get("next") or "analytics:dashboard")
