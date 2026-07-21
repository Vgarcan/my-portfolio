import uuid

from django.db import models


class Visitor(models.Model):
    """A pseudonymous browser, identified by a hashed first-party token."""

    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    first_seen = models.DateTimeField(auto_now_add=True, db_index=True)
    last_seen = models.DateTimeField(db_index=True)
    first_ip = models.GenericIPAddressField(null=True, blank=True)
    last_ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    pageview_count = models.PositiveIntegerField(default=0)
    session_count = models.PositiveIntegerField(default=1)
    is_known_bot = models.BooleanField(default=False, db_index=True)
    max_risk_score = models.PositiveSmallIntegerField(default=0)
    last_user_agent = models.TextField(blank=True)
    last_country = models.CharField(max_length=2, blank=True, db_index=True)
    last_city = models.CharField(max_length=120, blank=True)

    class Meta:
        ordering = ("-last_seen",)

    def __str__(self):
        return f"{self.token_hash[:12]}… ({self.pageview_count} views)"

    @property
    def short_id(self):
        return self.token_hash[:12]

    @property
    def is_returning(self):
        return self.session_count > 1 or self.pageview_count > 1


class PageView(models.Model):
    request_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    visitor = models.ForeignKey(
        Visitor, related_name="pageviews", on_delete=models.CASCADE
    )
    occurred_at = models.DateTimeField(auto_now_add=True, db_index=True)
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=1000, db_index=True)
    status_code = models.PositiveSmallIntegerField(db_index=True)
    response_ms = models.PositiveIntegerField(default=0)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    country = models.CharField(max_length=2, blank=True, db_index=True)
    city = models.CharField(max_length=120, blank=True)
    user_agent = models.TextField(blank=True)
    referrer = models.TextField(blank=True)
    device_type = models.CharField(max_length=20, blank=True, db_index=True)
    browser = models.CharField(max_length=40, blank=True)
    is_bot = models.BooleanField(default=False, db_index=True)
    bot_reason = models.CharField(max_length=255, blank=True)
    risk_score = models.PositiveSmallIntegerField(default=0, db_index=True)
    requests_per_minute = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ("-occurred_at",)
        indexes = [
            models.Index(fields=("occurred_at", "is_bot")),
            models.Index(fields=("occurred_at", "risk_score")),
            models.Index(fields=("ip_address", "occurred_at")),
        ]

    def __str__(self):
        return f"{self.method} {self.path} [{self.status_code}]"

    @property
    def severity(self):
        if self.risk_score >= 80:
            return "critical"
        if self.risk_score >= 60:
            return "high"
        if self.risk_score >= 35:
            return "medium"
        return "low"


class SecurityEvent(models.Model):
    EVENT_TYPES = (
        ("rate_spike", "Traffic spike"),
        ("scanner", "Vulnerability scan"),
        ("automation", "Suspicious automation"),
        ("bad_request", "Suspicious request"),
    )
    SEVERITIES = (
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    )

    occurred_at = models.DateTimeField(auto_now_add=True, db_index=True)
    visitor = models.ForeignKey(
        Visitor, related_name="security_events", null=True, blank=True,
        on_delete=models.SET_NULL,
    )
    pageview = models.OneToOneField(
        PageView, related_name="security_event", null=True, blank=True,
        on_delete=models.SET_NULL,
    )
    event_type = models.CharField(max_length=30, choices=EVENT_TYPES, db_index=True)
    severity = models.CharField(max_length=10, choices=SEVERITIES, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    path = models.CharField(max_length=1000, blank=True)
    summary = models.CharField(max_length=255)
    evidence = models.JSONField(default=dict, blank=True)
    resolved = models.BooleanField(default=False, db_index=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="resolved_security_events",
    )

    class Meta:
        ordering = ("-occurred_at",)
        indexes = [models.Index(fields=("resolved", "severity", "occurred_at"))]

    def __str__(self):
        return f"{self.get_severity_display()}: {self.summary}"
