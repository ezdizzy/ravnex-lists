# ravnex-lists — the lists hub

Validated per-service routing lists and DPI strategies for the Ravnex OpenWrt
app (`ezdizzy/ravnex`). CI aggregates upstream sources, VALIDATES every file
(an empty or broken upstream list never ships — the build falls back to a
reserve source or honestly omits the category), splits zip archives into
small per-category files, converts raw text lists into sing-box rule-set
JSON, and publishes everything as one release with a full-provenance
`manifest.json`.

The router never downloads megabyte-scale archives from here: every
published category is a small, exact file.

## Attribution (data belongs to its upstream authors)

Every release ships `manifest.json` where each category carries its exact
origin (repo, source kind, license, attribution line). Summary of the
sources used:

| Source | License | Note |
|---|---|---|
| itdoginfo/allow-domains | none | data consumed/republished with attribution |
| runetfreedom/russia-v2ray-rules-dat | GPL-3.0 | zip split into per-category .srs |
| MetaCubeX/meta-rules-dat | MIT-derived (v2fly data), repack license unstated | attributed |
| Greeg0ry/b4geoip-forkop | not stated | attributed |
| 1andrevich/Re-filter-lists | MIT | mass layer (opt-in) |
| antifilter.download / antifilter.community | none | attributed |
| eduard256/russia-blocked-ips | MIT | attributed |
| Noktomezo/RussiaFancyLists | MIT | NOT aggregated (33 MB mega-aggregate, excluded by design) |
| zemidala/nfqws2-strategies | none | strategies republished with attribution |
| CherretGit/zaprett-repo | none | strategies republished with attribution |

If you are an upstream author and want your data handled differently,
open an issue — it will be honored.

## What is deliberately NOT built here

Mega-aggregates that promise "everything" (700k+ domain lists, 33 MB
aggregates, whole geosite.dat/geoip.dat trees). The product philosophy:
small precise per-service lists chosen by the user, plus the app's
automation engine that classifies and learns blocked sites on the box.

## Files

- `sources.json` — the machine-readable build catalog (categories, sources
  and reserves, validation rules).
- `scripts/build_lists.py` — the builder (Python 3, stdlib only).
- `dist/` (per run) — `cat-<id>.srs|json`, `strategies/…`, `manifest.json`.

## Scheduling

Manual `workflow_dispatch` plus a default 6-hour cron; the cadence is
tuned on the hub settings page as the validation rules settle.
