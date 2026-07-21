from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from analytics.models import PageView, SecurityEvent, Visitor


class Command(BaseCommand):
    help = "Delete traffic analytics older than the configured retention period."

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int, default=None)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        days = options["days"] or getattr(settings, "ANALYTICS_RETENTION_DAYS", 90)
        if days < 1:
            raise CommandError("Retention must be at least one day.")
        cutoff = timezone.now() - timedelta(days=days)
        views = PageView.objects.filter(occurred_at__lt=cutoff)
        events = SecurityEvent.objects.filter(occurred_at__lt=cutoff)
        view_count = views.count()
        event_count = events.count()
        if options["dry_run"]:
            self.stdout.write(
                f"Would delete {view_count} page views and {event_count} security events."
            )
            return
        events.delete()
        views.delete()
        orphaned, _ = Visitor.objects.filter(pageviews__isnull=True).delete()
        self.stdout.write(self.style.SUCCESS(
            f"Deleted {view_count} page views, {event_count} security events "
            f"and {orphaned} orphaned visitor records."
        ))
