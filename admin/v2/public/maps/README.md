`protomaps-world-z4.pmtiles` is a whole-world Protomaps Basemap extract with
zoom levels 0 through 4. The archive is derived from OpenStreetMap and Natural
Earth data; the admin map keeps the required OpenStreetMap attribution visible.

It was extracted from the Protomaps daily build published for 2026-05-18:

```sh
go run github.com/protomaps/go-pmtiles@latest extract \
  https://build.protomaps.com/20260518.pmtiles \
  admin/v2/public/maps/protomaps-world-z4.pmtiles \
  --maxzoom=4
```
