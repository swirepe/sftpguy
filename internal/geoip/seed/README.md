This directory is embedded by the GeoIP manager.

Run `go generate ./internal/geoip` to download the optional seed databases:

- `GeoLite2-City.mmdb.gz`
- `dbip-city-lite.mmdb.gz`

The server can run without embedded seed databases. When GeoIP auto-update is
enabled, maintenance downloads missing databases into the configured GeoIP data
directory.
