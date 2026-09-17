# Changelog

## v2.1 — 2026-09-17 — DNS-existence awareness (false-CRITICAL fix)

### Fixed
- **NXDOMAIN no longer reported CRITICAL**: a domain that does not exist (confirmed by apex + probe query) now returns **OK — nothing to lock down**, is excluded from the CRITICAL action count and from `spoofable.txt`, and hints at the parent domain when you audit a subdomain/hostname by mistake
- **DNS SERVFAIL / resolver failure no longer yields a spoof verdict**: record existence is *unknown* → verdict is LOW "re-run before acting" instead of a bare CRITICAL built from zero data (a transient DoH outage could previously flag whole lists CRITICAL)
- Partial SERVFAIL (some lookups answered): verdict stands, failure noted per lookup
- Registered recordless domains stay **CRITICAL** (spoofing needs no website) but the verdict now says exactly that — "no site: spoofing needs no site — lock down with `v=spf1 -all` + `p=reject`"


## v2.0 — 2026-09-12

**The false-confidence release.** Classifier rebuilt from "do records exist" to receiver-behavior calibration.

### Added
- **Enforcement-voiding combo detection** — the headline feature:
  - SPF `+all` / `?all` / **missing `all` term entirely** (RFC 7208: implicit `+all` — any other IP passes) → HIGH **VOIDED**, attacker gets an aligned SPF pass → DMARC pass → inbox, even under `p=reject`
  - `pct=0` → nothing enforced, 100% delivered → policy is decorative → HIGH VOIDED
  - `pct<100` → partial enforcement flagged
  - `sp=` ≠ `p=` → subdomain inheritance hole flagged
  - SPF >10 DNS lookups → permerror risk (RFC 7208 §4.6.4)
  - Missing DKIM selector + only SPF auth leg → forwarder fragility flagged
  - null-SPF (`v=spf1 -all`) + `p=reject` + no DKIM correctly scored **OK** — receive-only lockdown is the *ideal* state, not a warning
- 9-case synthetic calibration suite + live regression, all passing
- Cloudflare DoH fallback (dns.google down → keep auditing)
- DKIM selector probing (12 common selectors)
- Display-name bypass test mode (`From: "Brand Customer Care" <you@your-real-domain>` — the `p=reject` survivor demo)
- Headless mode: `--audit "d1 d2"` / `--audit-file list.txt`, **exit code = worst severity (0–4)** for cron alerting
- Audit-only menu mode (passive, nothing sent — for domains you don't own)
- Trend mode: per-domain verdict history from JSONL snapshots
- Send logs (`send-log-*.csv`), dry-run `.eml` previews, batch cap, randomized pacing

### Changed
- Renamed from `spoof_tui` → **PostcardTUI**; `~/.spoof_tui_*` config/history auto-migrate
- Sub-inbox relay resolved dynamically via MX lookup (no hardcoded relay)

## v1.x — pre-history (privately circulated as spoof_tui / mailaudit / spoof_kit)
- Two-stage portfolio audit + live-fire sender, separate scripts
- Interactive wizard replaced the edit-in-nano workflow; audit/sender logic later folded into the single-script wizard
- Gmail 5.7.26 / Message-ID header minimums learned from live 550 bounces
