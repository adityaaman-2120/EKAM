# `deploy/data/` — optional enrichment databases

This directory is where you place the **MaxMind GeoLite2** databases that the
GeoIP enricher ([`ulpf/enrich/geoip.py`](../../ulpf/enrich/geoip.py)) uses:

| File | Purpose | Fields added |
|------|---------|--------------|
| `GeoLite2-City.mmdb` | geolocation | `country_code`, `country_name`, `city`, `latitude`, `longitude` |
| `GeoLite2-ASN.mmdb` | network ownership | `asn`, `asn_org` |

**Nothing here is committed.** `*.mmdb` is in `.gitignore`. The framework runs
fine with neither file present — the enricher logs one line, disables itself, and
the pipeline continues. GeoIP is a convenience, never a hard dependency.

## How to obtain GeoLite2

1. Create a **free MaxMind account**: <https://www.maxmind.com/en/geolite2/signup>
2. In the account portal, generate a **licence key**
   (*Account → Manage License Keys*).
3. Download the databases (choose the **binary `.mmdb`** format, GZIP archive):
   - GeoLite2 City — `GeoLite2-City_YYYYMMDD.tar.gz`
   - GeoLite2 ASN — `GeoLite2-ASN_YYYYMMDD.tar.gz`

   Either download from the web portal, or use MaxMind's `geoipupdate` tool with
   your account ID + licence key. **`geoipupdate` is run by you, out of band.**
   ULPF never calls it and never contacts MaxMind — auto-update is deliberately
   not wired in (`GeoIpEnricher.AUTO_UPDATE = False`).
4. Extract the `.mmdb` files and drop them here:

   ```
   deploy/data/GeoLite2-City.mmdb
   deploy/data/GeoLite2-ASN.mmdb
   ```

5. Point the config at them (or rely on these default paths):

   ```yaml
   # configs/ulpf.yaml
   enrich:
     geoip_db_path: deploy/data/GeoLite2-City.mmdb
     geoip_asn_db_path: deploy/data/GeoLite2-ASN.mmdb
   ```

   Install the reader package: `pip install 'ulpf[geoip]'` (adds `maxminddb`).

## Offline / air-gap

Once the `.mmdb` file is on disk, **every lookup is fully offline** — the reader
memory-maps the file and answers from it. No DNS, no API, no callbacks. This is
what makes GeoIP usable inside the air-gapped container: copy the file in with
the deployment artefact and refresh it out of band on whatever cadence your
policy allows.

## Licensing — read before distributing

- GeoLite2 databases are distributed by MaxMind under the
  **Creative Commons Attribution-ShareAlike 4.0 International License**, plus
  MaxMind's [GeoLite2 End User License Agreement](https://www.maxmind.com/en/geolite2/eula).
- Using the database to enrich your own logs is fine under a free account.
- **Redistributing the `.mmdb` file** (bundling it in an image, a release
  tarball, a shared drive for third parties, this git repository, …) is **not**
  permitted under the free licence and requires a **separate commercial
  licence** from MaxMind.
- Therefore: **do not commit `*.mmdb` to this repository** and do not add it to
  any build artefact you hand to another party. Each deployment obtains its own
  copy under its own MaxMind account.

## Attribution

If you surface GeoLite2-derived data in a product, include:

> This product includes GeoLite2 data created by MaxMind, available from
> <https://www.maxmind.com>.
