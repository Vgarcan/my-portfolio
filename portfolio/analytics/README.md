# Trace analytics

Private first-party traffic monitoring at `/ops/trace/`. Django staff access is
required; unauthenticated users are redirected to the existing admin login.

## Captured data

- Hashed first-party visitor ID, recurrence and sessions (30-minute inactivity gap)
- Timestamp, route, method, status, server response time and referrer
- Client IP, user-agent, coarse device/browser classification
- Country/city only when supplied by a trusted reverse proxy
- Bot, scanner and request-burst signals with a 0–100 risk score
- Reviewable security alerts and filtered CSV export

The detector is an observability layer, not a WAF. Put Cloudflare, a reverse
proxy rate limit or another edge control in front of the app to actually block
attacks. Very high-volume traffic is sampled to avoid turning an attack into an
unbounded database-write spike.

## Environment configuration

```text
ANALYTICS_ENABLED=True
ANALYTICS_RETENTION_DAYS=90
ANALYTICS_RATE_LIMIT_PER_MINUTE=60
ANALYTICS_ATTACK_SAMPLE_MULTIPLIER=3
ANALYTICS_TRUSTED_PROXIES=127.0.0.1,::1,192.168.2.104
ANALYTICS_REDIS_URL=redis://127.0.0.1:6379/2
```

`ANALYTICS_TRUSTED_PROXIES` accepts individual IPs and CIDR networks. Forwarded
IP and location headers are ignored unless the direct connection came from one
of these networks. If Cloudflare connects directly to Gunicorn, add its current
origin-facing networks; if Nginx on localhost is the only upstream, the defaults
are appropriate. `CF-Connecting-IP`, `CF-IPCountry`, `CF-IPCity` and
`X-Geo-City` are understood.

Redis is used only for short-lived, cross-worker rate counters and alert
deduplication. Raw visits remain in the primary Django database.

## Retention

Schedule this command daily (cron/systemd) so raw personal data expires:

```bash
./venv/bin/python manage.py purge_analytics
```

Use `--dry-run` to audit or `--days N` to override the configured period.
Because IP addresses and persistent identifiers can be personal data, document
the purpose and retention period in the site's privacy information and validate
the cookie/consent basis applicable to the deployment.
