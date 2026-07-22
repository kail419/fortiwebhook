# GeoIP database

Place a current MaxMind GeoLite2 Country database here:

```text
geoip/GeoLite2-Country.mmdb
```

The database is intentionally ignored by Git. Download and update it under
MaxMind's GeoLite2 license; the EMS monitor performs lookups locally and does
not send endpoint IP addresses to a third-party geolocation API.
