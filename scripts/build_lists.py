#!/usr/bin/env python3
"""ravnex-lists builder — aggregate, VALIDATE and publish per-category routing lists.

Design goals (the reason this hub exists):
  * an empty or broken upstream list must NEVER ship (the "source broke and
    we had to hardcode" incident class) — every category passes validations
    and, when suspicious, falls back to a reserve source or is honestly
    OMITTED from this run's manifest;
  * small exact files only — mega-aggregates are excluded by policy;
  * full provenance: every category in manifest.json carries origin,
    license, attribution, upstream tag and validation outcome.

Stdlib only (Python 3.9+). Outputs into --out (default dist/):
  cat-<id>.srs | cat-<id>.json, strategies/index.json, strategies/AS<asn>.json,
  manifest.json.
"""

import argparse
import datetime
import hashlib
import io
import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.request
import urllib.error
import zipfile

UA = "ravnex-lists-builder/1.0 (+https://github.com/ezdizzy/ravnex-lists)"
API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
REL_DL = "https://github.com/{repo}/releases/latest/download/{asset}"
SRS_MIN_BYTES = 32
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def http_get(url, token="", timeout=90, retries=2, binary=False):
    """GET with UA (+ optional GitHub token). Returns bytes or None."""
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    last_err = None
    for _ in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            return data if binary else data
        except Exception as e:  # noqa: BLE001 - any network failure is retryable
            last_err = e
    sys.stderr.write("fetch failed: %s (%s)\n" % (url, last_err))
    return None


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def github_release(repo, token):
    j = http_get("%s/repos/%s/releases/latest" % (API, repo), token=token, timeout=30)
    if not j:
        return None
    try:
        return json.loads(j.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None


def release_asset_url(repo, asset):
    return REL_DL.format(repo=repo, asset=asset)


# ── validation ────────────────────────────────────────────────────────────

def srs_valid(data):
    return bool(data) and len(data) >= SRS_MIN_BYTES and data[:3] == b"SRS"


def looks_like_html(data):
    head = data[:512].decode("utf-8", "replace").lower()
    return ("<html" in head) or ("<!doctype" in head)


def parse_list_entries(data):
    """Split a text list into stripped non-comment lines."""
    out = []
    text = data.decode("utf-8", "replace")
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def classify_entry(line):
    """House rule: domains → domain_suffix; IPs/CIDRs → ip_cidr; junk → None."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    try:
        net = ipaddress.ip_network(s, strict=False)
        return ("ip_cidr", str(net))
    except ValueError:
        pass
    try:
        ip = ipaddress.ip_address(s)
        return ("ip_cidr", str(ipaddress.ip_network("%s/32" % ip) if ip.version == 4 else ipaddress.ip_network("%s/128" % ip)))
    except ValueError:
        pass
    host = s.lower().lstrip(".")
    if DOMAIN_RE.match(host):
        return ("domain_suffix", host)
    return None


def to_source_ruleset(entries, kind):
    """Build a sing-box source rule-set document ({version:1, rules:[...]})."""
    seen, doms, nets = set(), [], []
    dropped = 0
    want = "ip_cidr" if kind == "ips" else "domain_suffix"
    for e in entries:
        c = classify_entry(e)
        if not c or c[0] != want:
            dropped += 1
            continue
        if c[1] in seen:
            continue
        seen.add(c[1])
        (nets if want == "ip_cidr" else doms).append(c[1])
    rules = []
    if want == "ip_cidr" and nets:
        rules.append({"ip_cidr": sorted(nets)})
    elif want == "domain_suffix" and doms:
        rules.append({"domain_suffix": sorted(doms)})
    doc = {"version": 1, "rules": rules}
    return doc, len(seen), dropped


# ── fetching one category through its ladder ──────────────────────────────

class ZipCache:
    """One zip download serves every zip-member category of the run."""

    def __init__(self):
        self.paths = {}

    def get(self, repo, asset, token, workdir):
        key = repo + "/" + asset
        if key in self.paths:
            return self.paths[key]
        rel = github_release(repo, token)
        digest = ""
        size = None
        tag = None
        if rel and rel.get("assets"):
            for a in rel["assets"]:
                if a.get("name") == asset:
                    d = a.get("digest") or ""
                    m = re.match(r"^sha256:([0-9a-f]{64})$", d)
                    digest = m.group(1) if m else ""
                    size = a.get("size")
                    tag = rel.get("tag_name")
        url = release_asset_url(repo, asset)
        data = http_get(url, token=token, timeout=300, binary=True)
        if data is None:
            self.paths[key] = None
            return None
        if size is not None and len(data) != size:
            sys.stderr.write("zip size mismatch for %s\n" % url)
            self.paths[key] = None
            return None
        if digest and sha256_hex(data) != digest:
            sys.stderr.write("zip sha256 mismatch for %s\n" % url)
            self.paths[key] = None
            return None
        path = os.path.join(workdir, "zip_" + hashlib.sha1(key.encode()).hexdigest()[:12] + ".zip")
        with open(path, "wb") as fh:
            fh.write(data)
        self.paths[key] = {"path": path, "tag": tag}
        return self.paths[key]


def fetch_category(cat, token, workdir, prev_counts, force, zc):
    """Returns (payload_bytes|None, meta). Tries origin, then reserves."""
    origin = cat["origin"]
    attempts = [origin] + cat.get("reserves", [])
    errors = []

    prev = prev_counts.get(cat["id"]) if prev_counts else None

    for idx, src in enumerate(attempts):
        kind = src.get("kind", "release")
        data = None
        meta = {"origin_url": None, "from_reserve": idx > 0, "upstream_tag": None,
                "upstream_published_at": None}
        try:
            if kind == "release":
                meta["origin_url"] = release_asset_url(src["repo"], src["asset"])
                rel = github_release(src["repo"], token)
                if rel and rel.get("tag_name"):
                    meta["upstream_tag"] = rel.get("tag_name")
                    meta["upstream_published_at"] = rel.get("published_at")
                data = http_get(meta["origin_url"], token=token, timeout=180, binary=True)
            elif kind == "release-zip":
                z = zc.get(src["repo"], src["asset"], token, workdir)
                if not z:
                    errors.append("zip unavailable: %s/%s" % (src["repo"], src["asset"]))
                    continue
                meta["origin_url"] = release_asset_url(src["repo"], src["asset"])
                meta["upstream_tag"] = z.get("tag")
                with zipfile.ZipFile(z["path"]) as zf:
                    member = src["member"]
                    if member not in zf.namelist():
                        errors.append("zip member missing: " + member)
                        continue
                    data = zf.read(member)
            elif kind == "raw":
                meta["origin_url"] = "%s/%s/%s/%s" % (RAW, src["repo"], src.get("branch", "main"), src["path"])
                data = http_get(meta["origin_url"], token=token, timeout=180, binary=True)
            elif kind == "site":
                meta["origin_url"] = src["url"]
                data = http_get(src["url"], token=token, timeout=180, binary=True)
        except Exception as e:  # noqa: BLE001
            errors.append("exception on %s: %s" % (src.get("repo"), e))
            data = None
        if data is None:
            errors.append("download failed: %s" % meta["origin_url"])
            continue
        meta["sha256"] = sha256_hex(data)
        meta["bytes"] = len(data)
        ok, note, entries_count = validate_payload(cat, data)
        if not ok:
            errors.append("validation failed on %s: %s" % (meta["origin_url"], note))
            continue
        if prev and not force:
            pe, pb = prev.get("entries"), prev.get("bytes")
            if entries_count is not None and pe:
                if entries_count * 2 < pe:
                    errors.append("suspect shrink: %d -> %d entries" % (pe, entries_count))
                    continue
            elif entries_count is None and pb and len(data) * 2 < pb:
                errors.append("suspect shrink: %d -> %d bytes" % (pb, len(data)))
                continue
        meta["validation"] = note
        return data, meta
    return None, {"errors": errors}


def validate_payload(cat, data):
    """Returns (ok, note, entries_count_or_None)."""
    fmt = cat["format"]
    if fmt == "srs":
        if not srs_valid(data):
            return False, "not an SRS binary or too small", None
        return True, "srs magic ok (%d bytes)" % len(data), None
    if fmt in ("source-json", "txt-domains", "txt-ips"):
        if looks_like_html(data):
            return False, "payload looks like an HTML error page", None
        entries = parse_list_entries(data)
        vmin = cat.get("validate", {}).get("min_entries", 10)
        if len(entries) < vmin:
            return False, "only %d entries (< %d)" % (len(entries), vmin), None
        # conversion happens later; here we sanity-count what would survive
        want = "ip_cidr" if cat.get("validate", {}).get("expect", "domains") == "ips" else "domain_suffix"
        good = sum(1 for e in entries if classify_entry(e) is not None)
        return True, "%d lines, %d parseable" % (len(entries), good), len(entries)
    return False, "unknown format %s" % fmt, None


# ── main ──────────────────────────────────────────────────────────────────

def previous_counts(repo, token):
    """Entry counts + sizes from the LATEST release manifest (shrink guard)."""
    j = http_get("%s/repos/%s/releases/latest" % (API, repo), token=token, timeout=30)
    if not j:
        return {}
    try:
        rel = json.loads(j.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    for a in rel.get("assets", []):
        if a.get("name") == "manifest.json":
            data = http_get(a.get("browser_download_url"), token=token, timeout=60)
            if not data:
                return {}
            try:
                man = json.loads(data.decode("utf-8"))
            except Exception:  # noqa: BLE001
                return {}
            out = {}
            for k, v in man.get("categories", {}).items():
                out[k] = {"entries": v.get("entries") if isinstance(v.get("entries"), int) else None,
                          "bytes": v.get("bytes") if isinstance(v.get("bytes"), int) else None}
            return out
    return {}


def build(out_dir, force, repo_self, token):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sources.json"), "rb") as fh:
        spec = json.loads(fh.read().decode("utf-8"))

    workdir = tempfile.mkdtemp(prefix="ravnexlists-")
    manifest = {
        "generated_at": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": "ravnex-lists-builder/1.0",
        "policy": "precision-first: small exact per-service lists; mega-aggregates excluded",
        "sources": {},
        "categories": {},
        "strategies": {},
        "excluded": spec.get("excluded", []),
    }

    # prefetch upstream release tags per repo (release-kind sources only —
    # site/raw "repos" are not GitHub repositories and would just 404)
    repos = set()
    for cat in spec["categories"]:
        o = cat["origin"]
        if o.get("kind") in ("release", "release-zip"):
            repos.add(o["repo"])
        for r in cat.get("reserves", []):
            if r.get("kind") in ("release", "release-zip"):
                repos.add(r["repo"])

    prev = previous_counts(repo_self, token)
    zc = ZipCache()

    for cat in spec["categories"]:
        cid = cat["id"]
        data, meta = fetch_category(cat, token, workdir, prev, force, zc)
        if data is None:
            manifest["categories"][cid] = {
                "status": "omitted",
                "errors": meta.get("errors", []),
                "layer": cat["layer"],
            }
            print("OMIT %s (no valid source this run)" % cid)
            continue
        dest = os.path.join(out_dir, cat["file"])
        entries = None
        if cat["format"] in ("source-json",):
            ents = parse_list_entries(data)
            want_ips = cat.get("validate", {}).get("expect", "domains") == "ips"
            doc, n_kept, n_drop = to_source_ruleset(ents, "ips" if want_ips else "domains")
            if not doc["rules"]:
                manifest["categories"][cid] = {"status": "omitted", "errors": ["conversion produced an empty rule-set"]}
                print("OMIT %s (empty after conversion)" % cid)
                continue
            with open(dest, "wb") as fh:
                fh.write(json.dumps(doc, ensure_ascii=False, sort_keys=True).encode("utf-8"))
            entries = n_kept
            meta["converted"] = {"accepted": n_kept, "dropped": n_drop}
            meta["sha256"] = sha256_hex(open(dest, "rb").read())
            meta["bytes"] = os.path.getsize(dest)
        else:
            with open(dest, "wb") as fh:
                fh.write(data)
            meta["sha256"] = sha256_hex(data)
            meta["bytes"] = len(data)
        manifest["categories"][cid] = {
            "status": "ok",
            "file": cat["file"],
            "format": cat["format"],
            "layer": cat["layer"],
            "coverage": cat.get("coverage", "direct"),
            "license": cat["origin"].get("license", ""),
            "attribution": cat["origin"].get("attribution", ""),
            "repo": cat["origin"].get("repo", ""),
            "entries": entries,
            "validation": meta.get("validation"),
            "from_reserve": meta.get("from_reserve", False),
            "origin_url": meta.get("origin_url"),
            "upstream_tag": meta.get("upstream_tag"),
            "upstream_published_at": meta.get("upstream_published_at"),
            "sha256": meta.get("sha256"),
            "bytes": meta.get("bytes"),
            "converted": meta.get("converted"),
        }
        print("OK   %-24s %8s B  reserve=%s" % (cid, meta.get("bytes"), meta.get("from_reserve")))

    # strategies (small JSON, validated passthrough with attribution)
    for st in spec.get("strategies", []):
        src = st["origin"]
        idx_url = "%s/%s/%s/index.json" % (RAW, src["repo"], src.get("branch", "main"))
        data = http_get(idx_url, token=token, timeout=60)
        if not data:
            manifest["strategies"][st["id"]] = {"status": "omitted", "errors": ["index fetch failed"]}
            continue
        try:
            index = json.loads(data.decode("utf-8"))
        except Exception:  # noqa: BLE001
            manifest["strategies"][st["id"]] = {"status": "omitted", "errors": ["index not JSON"]}
            continue
        if not isinstance(index.get("providers"), list):
            manifest["strategies"][st["id"]] = {"status": "omitted", "errors": ["index shape unexpected"]}
            continue
        os.makedirs(os.path.join(out_dir, "strategies"), exist_ok=True)
        with open(os.path.join(out_dir, "strategies", "index.json"), "wb") as fh:
            fh.write(json.dumps(index, ensure_ascii=False, sort_keys=True).encode("utf-8"))
        got, bad = 0, 0
        for p in index["providers"]:
            asn = p.get("asn")
            if not asn:
                continue
            dj = http_get("%s/%s/%s/data/AS%s.json" % (RAW, src["repo"], src.get("branch", "main"), asn), token=token, timeout=60)
            if not dj:
                bad += 1
                continue
            try:
                doc = json.loads(dj.decode("utf-8"))
                if not isinstance(doc.get("items"), list):
                    raise ValueError("items missing")
            except Exception:  # noqa: BLE001
                bad += 1
                continue
            with open(os.path.join(out_dir, "strategies", "AS%s.json" % asn), "wb") as fh:
                fh.write(json.dumps(doc, ensure_ascii=False, sort_keys=True).encode("utf-8"))
            got += 1
        manifest["strategies"][st["id"]] = {
            "status": "ok" if got else "omitted",
            "file": st["index"],
            "providers_published": got,
            "providers_failed": bad,
            "license": src.get("license", ""),
            "attribution": src.get("attribution", ""),
            "repo": src["repo"],
        }
        print("STRAT %-20s providers ok=%d failed=%d" % (st["id"], got, bad))

    # upstream provenance summary (repo → latest tag at build time)
    for repo in sorted(repos):
        rel = github_release(repo, token)
        manifest["sources"][repo] = (rel and rel.get("tag_name")) or None

    with open(os.path.join(out_dir, "manifest.json"), "wb") as fh:
        fh.write(json.dumps(manifest, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8"))

    ok_count = sum(1 for v in manifest["categories"].values() if v.get("status") == "ok")
    omit_count = sum(1 for v in manifest["categories"].values() if v.get("status") == "omitted")
    print("SUMMARY ok=%d omitted=%d strategies=%d" % (
        ok_count, omit_count, sum(1 for v in manifest["strategies"].values() if v.get("status") == "ok")))
    # a run with omissions is still a success (previous release stays intact);
    # catastrophic failure would have raised earlier.
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dist")
    ap.add_argument("--force", action="store_true", help="ignore the shrink-guard")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "ezdizzy/ravnex-lists"))
    args = ap.parse_args()
    token = os.environ.get("GITHUB_TOKEN", "")
    sys.exit(build(args.out, args.force, args.repo, token))


if __name__ == "__main__":
    main()
