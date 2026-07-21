from django.contrib import admin

from .models import PageView, SecurityEvent, Visitor


@admin.register(Visitor)
class VisitorAdmin(admin.ModelAdmin):
    list_display = (
        "short_id", "last_ip", "last_country", "pageview_count",
        "session_count", "max_risk_score", "last_seen",
    )
    list_filter = ("is_known_bot", "last_country")
    search_fields = ("token_hash", "first_ip", "last_ip", "last_user_agent")
    readonly_fields = tuple(field.name for field in Visitor._meta.fields)


@admin.register(PageView)
class PageViewAdmin(admin.ModelAdmin):
    list_display = (
        "occurred_at", "method", "path", "status_code", "ip_address",
        "country", "is_bot", "risk_score", "response_ms",
    )
    list_filter = ("is_bot", "country", "device_type", "status_code")
    search_fields = ("path", "ip_address", "user_agent", "visitor__token_hash")
    readonly_fields = tuple(field.name for field in PageView._meta.fields)
    date_hierarchy = "occurred_at"


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = (
        "occurred_at", "severity", "event_type", "ip_address", "summary", "resolved",
    )
    list_filter = ("severity", "event_type", "resolved")
    search_fields = ("ip_address", "path", "summary")
    readonly_fields = ("occurred_at", "visitor", "pageview", "evidence")
    date_hierarchy = "occurred_at"
