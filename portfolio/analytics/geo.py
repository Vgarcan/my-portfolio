import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path


# Visual centroids for large or geographically unusual countries. Other ISO
# codes are derived from the public-domain IANA timezone table available on the
# server, which gives broad coverage without a third-party geolocation API.
CENTROID_OVERRIDES = {
    "AR": (-64.0, -34.0), "AU": (134.0, -25.0), "BR": (-52.0, -10.0),
    "CA": (-106.0, 56.0), "CL": (-71.0, -33.0), "CN": (104.0, 35.0),
    "DE": (10.0, 51.0), "EG": (30.0, 27.0), "ES": (-4.0, 40.0),
    "FR": (2.0, 46.0), "GB": (-2.0, 54.0), "ID": (118.0, -2.0),
    "IN": (79.0, 22.0), "IT": (12.0, 42.0), "JP": (138.0, 36.0),
    "KE": (38.0, 1.0), "MX": (-102.0, 23.0), "NG": (8.0, 9.0),
    "NZ": (172.0, -41.0), "RU": (90.0, 60.0), "SA": (45.0, 24.0),
    "SG": (103.8, 1.35), "TR": (35.0, 39.0), "US": (-98.0, 39.0),
    "ZA": (24.0, -29.0),
}
COORDINATE_PATTERN = re.compile(
    r"^(?P<lat_sign>[+-])(?P<lat>\d{4}(?:\d{2})?)"
    r"(?P<lon_sign>[+-])(?P<lon>\d{5}(?:\d{2})?)$"
)


def _component(value, degree_digits, sign):
    degrees = int(value[:degree_digits])
    minutes = int(value[degree_digits:degree_digits + 2])
    seconds = int(value[degree_digits + 2:]) if len(value) > degree_digits + 2 else 0
    result = degrees + minutes / 60 + seconds / 3600
    return -result if sign == "-" else result


def _parse_coordinates(value):
    match = COORDINATE_PATTERN.fullmatch(value)
    if not match:
        return None
    latitude = _component(match["lat"], 2, match["lat_sign"])
    longitude = _component(match["lon"], 3, match["lon_sign"])
    return longitude, latitude


@lru_cache(maxsize=1)
def country_centroids():
    points = defaultdict(list)
    for filename in ("/usr/share/zoneinfo/zone1970.tab", "/usr/share/zoneinfo/zone.tab"):
        path = Path(filename)
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            columns = line.split("\t")
            if len(columns) < 2:
                continue
            coordinates = _parse_coordinates(columns[1])
            if coordinates:
                for country in columns[0].split(","):
                    points[country].append(coordinates)
        break

    centroids = {}
    for country, values in points.items():
        longitude = sum(item[0] for item in values) / len(values)
        latitude = sum(item[1] for item in values) / len(values)
        centroids[country] = (longitude, latitude)
    centroids.update(CENTROID_OVERRIDES)
    return centroids


def country_map_position(country_code):
    coordinates = country_centroids().get((country_code or "").upper())
    if not coordinates:
        return None
    longitude, latitude = coordinates
    # Equirectangular projection matching the inline SVG world map.
    x = (longitude + 180) / 360 * 100
    y = (90 - latitude) / 180 * 100
    return round(max(1.5, min(98.5, x)), 2), round(max(3, min(97, y)), 2)


def country_coordinates(country_code):
    """Return a country's approximate ``(latitude, longitude)`` centroid."""
    coordinates = country_centroids().get((country_code or "").upper())
    if not coordinates:
        return None
    longitude, latitude = coordinates
    return round(latitude, 4), round(longitude, 4)
