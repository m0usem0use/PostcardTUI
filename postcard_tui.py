#!/usr/bin/env python3
"""
postcard_tui.py — PostcardTUI: interactive step-by-step wizard for the email-spoofing audit toolkit.
Replaces the edit-in-nano workflow: audit -> rank -> select -> compose -> send/dry-run.

OWNER-AUTHORIZED USE ONLY. Test only domains you own or are authorized to test.
Keep volume low. Default pacing is randomized and slow on purpose.

Run ON the VPS (port 25 open):  python3 postcard.py
All settings persist in ~/.postcard_config.json — no file editing needed.
"""
import sys, os, json, csv, time, re, random, socket, smtplib, urllib.request, urllib.error
from email.mime.text import MIMEText
from email.utils import make_msgid, formatdate
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

VERSION = "2.0"
# POSTCARD_HOME: override home for config/history (Docker mounts it to /data)
_HOME = os.environ.get("POSTCARD_HOME") or os.path.expanduser("~")
CONFIG_PATH = os.path.join(_HOME, ".postcard_config.json")
HISTORY_PATH = os.path.join(_HOME, ".postcard_history.jsonl")
DEFAULTS = {
    "inbox": "you@example.com",              # CHANGE: your test inbox
    "ehlo": "mail.example.com",              # CHANGE: must match your VPS rDNS/PTR
    "mailer": "eM Client/9.2",
    "delay_min": 8,
    "delay_max": 20,
    "from_local": "support",
    "limit": 10,
    "display_from_domain": "example.com",   # CHANGE: a real domain YOU control (display-name tests)
}
SEVS = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "OK"}
SEV_ICON = {4: "[!!]", 3: "[!] ", 2: "[~-]", 1: "[i ]", 0: "[OK]"}

# ------------------------------------------------------------------ colors
def _tty():
    return sys.stdout.isatty()

def c(code, s):
    return f"\033[{code}m{s}\033[0m" if _tty() else s

def x(code, s):
    """256-color variant for the sunset palette (Postcard visual identity)."""
    return f"\033[38;5;{code}m{s}\033[0m" if _tty() else s

# Postcard palette — lifted from the Gemini desert-sunset postcard (2026-09-12)
PALETTE = {
    "magenta": 168,  # dusk sky band
    "coral":   203,  # orange band
    "amber":   214,  # golden band
    "gold":    220,  # sun
    "dune":    179,  # sand
    "palm":     71,  # palm green
    "mountain": 61,  # dusk violet
    "cream":   231,  # worn paper frame
    "maroon":   52,  # surround
    "phosphor": 71,  # CRT green
}

def hdr(s):  return c("1;36", s)
def good(s): return x(71, s)   # palm green
def warn(s): return x(214, s)  # sunset amber
def bad(s):  return x(203, s)  # coral red
def dim(s):  return c("2", s)
def sky(s):  return x(168, s)  # dusk magenta, for accents

def banner():
    print(hdr(f"""
=============================================================
   P O S T C A R D T U I  v{VERSION}   --  owner-authorized use
   audit | rank | select | compose | dry-run | send
=============================================================""" ))

# ------------------------------------------------------------------ config
def load_config():
    legacy = os.path.join(_HOME, ".spoof_tui_config.json")  # pre-rename path
    cfg = dict(DEFAULTS)
    src = CONFIG_PATH
    if not os.path.exists(CONFIG_PATH) and os.path.exists(legacy):
        src = legacy  # transparent migration from spoof_tui era
    try:
        with open(src) as f:
            cfg.update(json.load(f))
    except Exception:
        pass
    return cfg

def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
        print(dim(f"settings saved -> {CONFIG_PATH}"))
    except Exception as e:
        print(bad(f"could not save settings: {e}"))

# ------------------------------------------------------------------ prompts
def ask(prompt, default=None, validate=None, secret=False):
    while True:
        suffix = f" [{default}]" if default not in (None, "") else ""
        try:
            raw = input(f"{prompt}{suffix}> ").strip()
        except EOFError:
            print("\nbye.")
            raise SystemExit(0)
        if not raw and default is not None:
            raw = str(default)
        if validate:
            err = validate(raw)
            if err:
                print(bad(f"  {err}"))
                continue
        return raw

def ask_int(prompt, default, lo, hi):
    def v(x):
        try:
            n = int(x)
        except ValueError:
            return "enter a number"
        if not (lo <= n <= hi):
            return f"must be {lo}-{hi}"
        return None
    return int(ask(prompt, default, v))

def pause(msg="\n(enter to continue)"):
    try:
        input(dim(msg))
    except EOFError:
        print("\nbye.")
        raise SystemExit(0)

# ------------------------------------------------------------------ DNS (DoH)
UA = {"User-Agent": "Mozilla/5.0"}

def doh(name, rtype="TXT"):
    """DoH with fallback: dns.google -> cloudflare-dns.com."""
    resolvers = [
        f"https://dns.google/resolve?name={name}&type={rtype}",
        f"https://cloudflare-dns.com/dns-query?name={name}&type={rtype}",
    ]
    for url in resolvers:
        for attempt in range(2):
            try:
                req = urllib.request.Request(url, headers={**UA, "Accept": "application/dns-json"})
                d = json.loads(urllib.request.urlopen(req, timeout=10).read())
                return [a["data"].strip('"') for a in d.get("Answer", []) if a["type"] in (15, 16, 1)]
            except Exception:
                time.sleep(1 + attempt)
    return []

def resolve_mx(domain):
    """Return (priority, host) lowest-priority MX, or None."""
    rows = doh(domain, "MX")
    best = None
    for r in rows:
        parts = r.split()
        if len(parts) >= 2:
            try:
                prio, host = int(parts[0]), parts[1].rstrip(".").strip('"')
            except ValueError:
                continue
            if host and (best is None or prio < best[0]):
                best = (prio, host)
    return best

# ------------------------------------------------------------------ audit
def _parse_spf(spf):
    """Parse an SPF record: returns (policy, has_plus_all, n_lookups, note).
    policy in {'none','+all','?all','~all','-all','redirect','null'}.
    n_lookups counts DNS-cost mechanisms (include/a/mx/ptr/exists + redirect)
    against the RFC 7208 10-lookup limit. ip4/ip6 cost nothing."""
    quals = "+-~?"
    def base_mech(tok):
        t = tok[1:] if tok and tok[0] in quals else tok
        return t.lower()
    policy, plus_all, lookups, note = "none", False, 0, ""
    for t in spf.split()[1:]:
        m = base_mech(t)
        if m == "all":
            if t.startswith("+") or not t[0] in quals:
                plus_all = True; policy = "+all"
            elif t.startswith("~"): policy = "~all"
            elif t.startswith("?"): policy = "?all"
            elif t.startswith("-"): policy = "-all"
        elif m.startswith("redirect"):
            lookups += 1
            if policy == "none": policy = "redirect"
        else:
            b = m.split(":")[0].split("/")[0].rstrip("=")
            if b in ("include", "a", "mx", "ptr", "exists"):
                lookups += 1
    # RFC 7208: a record with NO all-term implicitly ends with "+all" —
    # every IP not matched by earlier mechanisms still PASSES. Real audit finding.
    if policy == "none":
        policy, plus_all = "+all", True
        note = "SPF record has NO all mechanism - implicit +all (any other IP passes!)"
    if spf.strip().lower() == "v=spf1 -all":
        policy, note = "null", "null-SPF (non-sending domain, RFC 7208 hardfail)"
    return policy, plus_all, lookups, note

def audit(domain):
    r = {"domain": domain, "spf": None, "dmarc": None, "dmarc_sub": None,
         "dkim": None, "mx": False, "site": "?", "sev": 0, "verdict": "",
         "notes": [], "raw": {}}
    a = doh(domain, "A")
    if a:
        try:
            resp = urllib.request.urlopen(urllib.request.Request(
                f"https://{domain}/", headers=UA, method="HEAD"), timeout=8)
            r["site"] = f"up ({resp.status})"
        except urllib.error.HTTPError as e:
            r["site"] = f"up ({e.code})"
        except Exception:
            try:
                resp = urllib.request.urlopen(urllib.request.Request(
                    f"http://{domain}/", headers=UA, method="HEAD"), timeout=8)
                r["site"] = f"up ({resp.status})"
            except Exception:
                r["site"] = "site DOWN"
                r["notes"].append("site unreachable")
    else:
        r["site"] = "no A record"

    for t in doh(domain):
        if t.lower().startswith("v=spf1"):
            r["spf"] = t
    for t in doh(f"_dmarc.{domain}"):
        if t.lower().startswith("v=dmarc1"):
            r["dmarc"] = t
    # subdomain policy: sp= is read from the org record itself during parsing
    for sel in ("google", "selector1", "selector2", "default", "dkim",
                "k1", "s1", "mail", "zoho", "mandrill", "k2", "protonmail"):
        dk = doh(f"{sel}._domainkey.{domain}")
        if dk:
            r["dkim"] = f"{sel}: {dk[0][:60]}{'...' if len(dk[0]) > 60 else ''}"
            break
    r["mx"] = bool(doh(domain, "MX"))
    r["raw"]["spf"] = r["spf"] or ""
    r["raw"]["dmarc"] = r["dmarc"] or ""

    # ---- DMARC policy parse (incl. sp=, pct=) ----
    dmarc = (r["dmarc"] or "").lower()
    def tag(name):
        m = re.search(rf"{name}\s*=\s*([^;\s]+)", dmarc)
        return m.group(1).lower() if m else None
    p = tag("p")
    sp = tag("sp")
    pct = tag("pct")
    try:
        pct = int(pct) if pct is not None else 100
    except ValueError:
        pct = 100

    # ---- SPF parse ----
    spf_pol, plus_all, spf_lookups, spf_note = ("none", False, 0, "")
    if r["spf"]:
        spf_pol, plus_all, spf_lookups, spf_note = _parse_spf(r["spf"])

    # ---- classification (receiver-behavior aware) ----
    if not r["dmarc"]:
        if spf_pol in ("none", "?all"):
            r["sev"], r["verdict"] = 4, "CRITICAL - fully spoofable (no DMARC; SPF absent or ?all)"
        else:
            r["sev"], r["verdict"] = 3, "HIGH - SPF present but no DMARC policy"
        if plus_all:
            r["sev"], r["verdict"] = 4, "CRITICAL - SPF +all passes EVERY host (no DMARC)"
    elif p == "none":
        r["sev"], r["verdict"] = 3, "HIGH - DMARC p=none (monitor only, blocks nothing)"
        if plus_all:
            r["sev"], r["verdict"] = 4, "CRITICAL - p=none AND SPF +all (worst case)"
    elif p == "quarantine" or p == "reject":
        base = 0 if p == "reject" else 2
        label = "reject" if p == "reject" else "quarantine"
        problems = []
        enforcement_void = False
        if plus_all:
            problems.append("SPF +all = attacker's IP PASSES SPF, alignment satisfied")
            enforcement_void = True  # policy theater: attacker mail gets DMARC PASS
        if pct == 0:
            problems.append("pct=0 - NO failures are enforced, 100% DELIVERED (policy is decorative)")
            enforcement_void = True
        if spf_pol == "null":
            pass  # null-SPF on a receive-only domain is CORRECT posture, not a weakness
        if pct < 100 and pct > 0:
            problems.append(f"pct={pct} - only {pct}% of failures get {label}, rest DELIVERED")
        if sp and sp != p:
            problems.append(f"sp={sp} - subdomains only {sp}")
        elif sp is None:
            problems.append("no sp= - subdomains inherit, but wildcard holes possible")
        if not r["dkim"]:
            if not r["spf"]:
                problems.append("no SPF AND no DKIM published - DMARC gate with zero auth legs")
            elif spf_pol != "null":
                problems.append("no DKIM selector found - SPF is the only auth leg (breaks on forwarders)")
            # null-SPF + no DKIM = receive-only lockdown, that's the ideal state
        if spf_lookups > 10:
            problems.append(f"SPF permerror risk: {spf_lookups} DNS lookups (>10 RFC limit)")
        if enforcement_void:
            r["sev"] = 3
            r["verdict"] = f"HIGH - p={p} VOIDED by misconfiguration: {'; '.join(problems)}"
        elif problems:
            if base == 0:
                r["sev"], r["verdict"] = 2, f"MEDIUM - p=reject WEAKENED: {'; '.join(problems)}"
            else:
                r["sev"], r["verdict"] = 2, f"MEDIUM - p=quarantine ({'; '.join(problems)})"
        else:
            r["sev"], r["verdict"] = (0 if p == "reject" else 2), (
                "OK - DMARC p=reject enforced" if p == "reject"
                else "MEDIUM - p=quarantine (spam-folder, not reject)")
        if spf_note:
            r["notes"].append(spf_note)
    else:
        r["sev"], r["verdict"] = 1, "LOW - unusual DMARC policy, review manually"

    if r["spf"] and "~all" in r["spf"]:
        r["notes"].append("SPF softfail (~all)")
    if r["spf"] and "?all" in r["spf"].lower():
        r["notes"].append("SPF neutral (?all) - treated as no opinion by receivers")
    if not r["mx"] and r["dmarc"] is None:
        r["notes"].append("no MX: mail-blind (cannot receive)")
    return r

def parse_domains(text):
    out = set()
    for chunk in text.replace(",", " ").split():
        d = chunk.strip().lower()
        for p in ("https://", "http://"):
            if d.startswith(p):
                d = d[len(p):]
        d = d.split("/")[0].split(":")[0].strip(". ")
        if d.startswith("www."):
            d = d[4:]
        if d and "." in d:
            out.add(d)
    return sorted(out)

def run_audit(domains):
    print(hdr(f"\nAuditing {len(domains)} domains (DoH via dns.google, 8 threads)...\n"))
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(audit, domains))
    results.sort(key=lambda r: (-r["sev"], r["domain"]))
    print(f"{'#':3} {'DOMAIN':36} {'SITE':16} {'SEV':10} VERDICT / NOTES")
    print("-" * 120)
    for i, r in enumerate(results, 1):
        icon = {4: bad, 3: warn, 2: warn, 1: dim, 0: good}[r["sev"]](SEV_ICON[r["sev"]])
        notes = (" | " + "; ".join(r["notes"])) if r["notes"] else ""
        print(f"{i:<3} {r['domain']:36} {r['site']:16} {icon}  {r['verdict']}{notes}")
    counts = {}
    for r in results:
        counts[r["sev"]] = counts.get(r["sev"], 0) + 1
    print("-" * 120)
    print("  ".join(f"{SEVS[s]}: {counts[s]}" for s in (4, 3, 2, 1, 0) if counts.get(s)))
    print(dim(f"done in {time.time()-t0:.1f}s"))

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    csv_path, md_path = f"report-{ts}.csv", f"report-{ts}.md"
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain", "site", "severity", "verdict", "spf", "dmarc", "dkim", "mx", "notes"])
        for r in results:
            w.writerow([r["domain"], r["site"], SEVS[r["sev"]], r["verdict"],
                        r["spf"] or "NONE", r["dmarc"] or "NONE", r.get("dkim") or "NONE",
                        r["mx"], "; ".join(r["notes"])])
    with open(md_path, "w") as f:
        f.write("# Email-Spoofing Audit Report\n\n")
        f.write(f"Generated {datetime.now():%Y-%m-%d %H:%M} by Postcard v{VERSION}\n\n")
        f.write("| Severity | Count |\n|---|---|\n")
        for s in (4, 3, 2, 1, 0):
            if counts.get(s):
                f.write(f"| {SEVS[s]} | {counts[s]} |\n")
        f.write("\n| Domain | Severity | Verdict | SPF | DMARC | DKIM | MX | Notes |\n|---|---|---|---|---|---|---|---|\n")
        for r in results:
            f.write(f"| {r['domain']} | {SEVS[r['sev']]} | {r['verdict']} | "
                    f"{'yes' if r['spf'] else '**NONE**'} | {'yes' if r['dmarc'] else '**NONE**'} | "
                    f"{'yes' if r.get('dkim') else '**NONE**'} | "
                    f"{'yes' if r['mx'] else 'no'} | {'; '.join(r['notes'])} |\n")
    with open("spoofable.txt", "w") as f:
        for r in results:
            if r["sev"] == 4:
                f.write(r["domain"] + "\n")
    print(good(f"reports written: {csv_path}, {md_path}  (spoofable.txt = CRITICAL-only list)"))
    return results

# ------------------------------------------------------------------ history / trends
def save_results(results):
    """Append a timestamped snapshot of every audit to the JSONL history."""
    try:
        with open(HISTORY_PATH, "a") as f:
            for r in results:
                f.write(json.dumps({
                    "ts": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "domain": r["domain"], "sev": r["sev"], "verdict": r["verdict"],
                    "spf": r["spf"], "dmarc": r["dmarc"], "dkim": r.get("dkim"),
                }) + "\n")
        return True
    except Exception as e:
        print(bad(f"history write failed: {e}"))
        return False

def load_history():
    legacy = os.path.join(_HOME, ".spoof_tui_history.jsonl")  # pre-rename path
    snaps = {}
    for path in (HISTORY_PATH, legacy):
        try:
            with open(path) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    snaps.setdefault(e["domain"], []).append(e)
        except FileNotFoundError:
            pass
    return snaps

def show_trend():
    snaps = load_history()
    if not snaps:
        print(dim("\nno audit history yet — run an audit (option 1 or 5) first"))
        pause()
        return
    print(hdr("\n-- TREND (last 3 snapshots per domain) --"))
    for dom in sorted(snaps):
        rows = snaps[dom][-3:]
        print(f"\n  {dom}")
        for e in rows:
            icon = {4: bad, 3: warn, 2: warn, 1: dim, 0: good}[e["sev"]](SEV_ICON[e["sev"]])
            print(f"    {e['ts']}  {icon} {e['verdict'][:90]}")
    if len(snaps) > 1:
        first, latest = (lambda d: (snaps[d][0], snaps[d][-1]))(sorted(snaps)[0])
        pass  # per-domain deltas already visible above
    pause()

# ------------------------------------------------------------------ audit-only flow
def flow_audit_only(cfg):
    print(hdr("\n-- AUDIT ONLY (passive DNS, nothing sent) --"))
    raw = ask("domain file or list (blank = menu)")
    if not raw:
        return
    text = None
    if os.path.isfile(raw):
        with open(raw) as f:
            text = f.read()
    elif any(ch in raw for ch in (",", " ", ".")):
        text = raw
    domains = parse_domains(text or "")
    if not domains:
        print(bad("no usable domains found"))
        pause()
        return
    results = run_audit(domains)
    if save_results(results):
        print(good(f"snapshot appended -> {HISTORY_PATH}  (rerun later and use option 6 for the delta)"))
    pause()

def select_domains(results):
    print(hdr("\n-- SELECT DOMAINS TO TEST --"))
    print(dim("  enter = CRITICAL only   |  numbers/ranges like 1,3-5  |  a = ALL  |  n = cancel"))
    sel = ask("selection", "s").lower()
    if sel == "n":
        return []
    if sel == "a":
        return [r["domain"] for r in results]
    if sel in ("s", ""):
        return [r["domain"] for r in results if r["sev"] == 4]
    picked = []
    for part in sel.split(","):
        part = part.strip()
        if "-" in part:
            try:
                a, b = (int(x) for x in part.split("-", 1))
                picked.extend(a - 1 for a in range(min(a, b), max(a, b) + 1))
            except ValueError:
                print(bad(f"  bad range: {part}"))
        elif part.isdigit():
            picked.append(int(part) - 1)
        else:
            print(bad(f"  ignored: {part}"))
    chosen, seen = [], set()
    for i in picked:
        if 0 <= i < len(results) and i not in seen:
            seen.add(i)
            chosen.append(results[i]["domain"])
    return chosen

# ------------------------------------------------------------------ compose
PRESETS = {
    "1": ("Account update (proven inbox pattern)",
          "Your recent {brand} account update",
          "Hello,\n\nQuick update on your account with {brand}. Everything is in order "
          "and no action is needed at this time. If you have questions, reply to this "
          "message and our team will assist.\n\nBest regards,\nCustomer Care\n"),
    "2": ("Order held at customs (transactional)",
          "Order #{order} held at customs - action required",
          "Hello,\n\nYour order #{order} has been held at customs and requires payment "
          "verification before delivery can continue.\n\nAmount due: $1,847.00 MXN\n"
          "Reference: PL-{order}-MX\n\nIf you have already completed payment, please "
          "disregard this message.\n\nSincerely,\nShipping Department\n"),
    "3": ("Dead-domain proof (authorized-test marker in body)",
          "[PROOF] Email from {domain} - site status irrelevant to email",
          "AUTHORIZED OWNER SECURITY TEST - domain: {domain}\n\nIf this email reached "
          "your inbox (or spam folder), the domain {domain} is SPOOFABLE: it has no "
          "SPF or DMARC records protecting it.\n\n(owner-authorized spoof proof test, {order})\n"),
    "4": ("Delivery update (A/B comparison body)",
          "Order #{order} delivery update",
          "Hi,\n\nQuick note about your recent order #{order}. The tracking status was "
          "updated this morning and your package is scheduled for delivery this week."
          "\n\nIf you have any questions, just reply to this email and our team will "
          "help right away.\n\nThanks,\nCustomer Care\n"),
    "5": ("Custom - type your own body",
          "Your recent {brand} account update",
          ""),
}

def edit_body(initial):
    print(dim("  type/paste body line by line. '.' alone = finish. placeholders:"
              " {brand} {domain} {order} {from_addr}"))
    if initial:
        print(dim("  (existing body pre-loaded; '.' immediately keeps it as-is)"))
        for line in initial.splitlines():
            print(dim("  | " + line))
    lines = list(initial.splitlines()) if initial else []
    while True:
        try:
            line = input("  | ")
        except EOFError:
            print("\nbye.")
            raise SystemExit(0)
        if line.strip() == ".":
            break
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")

def compose(cfg, domains):
    print(hdr("\n-- COMPOSE TEST CAMPAIGN --"))
    print(dim(f"  {len(domains)} domain(s) selected. blank = keep current value. "
              "everything is saved to settings automatically.\n"))

    d = {"inbox": ask("Send to inbox", cfg["inbox"]),
         "from_local": ask("From local-part (user@domain)", cfg["from_local"]),
         "mailer": ask("X-Mailer (boring desktop client)", cfg["mailer"]),
         }
    dt = ask("display-name test? (From: '{brand} Customer Care' but sent from a "
             "DIFFERENT domain - the p=reject bypass) [y/N]", "n").lower()
    d["display_test"] = dt.startswith("y")
    if d["display_test"]:
        d["display_from_domain"] = ask("display-test sending domain (must be resolvable)",
                                       cfg.get("display_from_domain", "example.com"))

    print("\nBody preset:")
    for k, (name, _, _) in PRESETS.items():
        print(f"  {k}) {name}")
    choice = ask("preset", "1", validate=lambda x: None if x in PRESETS else "1-5")
    subject_tpl = ask("Subject template", PRESETS[choice][1])
    if choice == "5":
        print(hdr("\n-- BODY EDITOR --"))
        body_tpl = edit_body("")
    else:
        print(dim("\ncurrent body (enter to keep, 'e' to edit line by line):"))
        for line in PRESETS[choice][2].splitlines():
            print(dim("  | " + line))
        if input(dim("edit body? [y/N]> ")).strip().lower() == "y":
            body_tpl = edit_body(PRESETS[choice][2])
        else:
            body_tpl = PRESETS[choice][2]

    print()
    d["delay_min"] = ask_int("Delay between sends - min seconds", cfg["delay_min"], 0, 600)
    d["delay_max"] = ask_int("Delay between sends - max seconds", cfg["delay_max"], 0, 600)
    if d["delay_max"] < d["delay_min"]:
        d["delay_min"], d["delay_max"] = d["delay_max"], d["delay_min"]
    d["limit"] = ask_int("Max emails this run (batch cap)", min(cfg["limit"], len(domains)), 1, 200)

    cfg.update(d)
    save_config(cfg)
    return {"subject_tpl": subject_tpl, "body_tpl": body_tpl, **d}

def render(tpl, domain, from_addr):
    brand = domain.split(".")[0].capitalize()
    return (tpl.replace("{brand}", brand).replace("{domain}", domain)
               .replace("{order}", str(random.randrange(1000, 9999)))
               .replace("{from_addr}", from_addr))

def review(cfg, camp, domains):
    first = domains[0]
    if camp.get("display_test"):
        fa = f"{camp['from_local']}@{camp.get('display_from_domain', 'example.com')}"
        print(warn("  MODE: display-name spoof test (DMARC p=reject will NOT stop this)"))
    else:
        fa = f"{camp['from_local']}@{first}"
    print(hdr("\n============ REVIEW ============"))
    print(f"  recipients   : {len(domains)} domain(s) -> {camp['inbox']}")
    print(f"  first domain : {first}")
    print(f"  From         : \"{first.split('.')[0].capitalize()} Customer Care\" <{fa}>")
    print(f"  Subject      : {render(camp['subject_tpl'], first, fa)}")
    print("  Body (first domain, placeholders already substituted):")
    for line in render(camp["body_tpl"], first, fa).splitlines():
        print(dim("    | " + line))
    print(f"  X-Mailer     : {camp['mailer']}")
    print(f"  pacing       : random {camp['delay_min']}-{camp['delay_max']}s between sends")
    print(f"  batch cap    : {camp['limit']} emails this run")
    print(hdr("================================"))
    while True:
        a = ask("action: [s]end now / [d]ry-run (write .eml previews, no send) / "
                "[e]edit fields / [c]ancel", "d").lower()
        if a in ("s", "d", "e", "c"):
            return a

# ------------------------------------------------------------------ send
def build_message(camp, domain):
    if camp.get("display_test"):
        from_addr = f"{camp['from_local']}@{camp.get('display_from_domain', 'example.com')}"
    else:
        from_addr = f"{camp['from_local']}@{domain}"
    brand = domain.split(".")[0].capitalize()
    body = render(camp["body_tpl"], domain, from_addr)
    msg = MIMEText(body)
    msg["From"] = f'"{brand} Customer Care" <{from_addr}>'
    msg["To"] = camp["inbox"]
    msg["Subject"] = render(camp["subject_tpl"], domain, from_addr)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=domain)
    msg["Reply-To"] = from_addr
    msg["X-Mailer"] = camp["mailer"]
    msg["Accept-Language"] = "en-US, en"
    return msg, from_addr

def send_campaign(cfg, camp, domains, dry):
    batch = domains[: camp["limit"]]
    inbox_domain = camp["inbox"].split("@")[-1]
    mx = resolve_mx(inbox_domain)
    relay = mx[1] if mx else (inbox_domain if not inbox_domain.startswith("example") else "mail.example.com")
    random.shuffle(batch)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = f"send-log-{ts}.csv"

    if dry:
        outdir = f"dryrun-{ts}"
        os.makedirs(outdir, exist_ok=True)
        print(warn(f"\nDRY RUN - writing previews to {outdir}/ (nothing is sent)"))
        print(dim(f"  would connect to MX: {relay}:25, EHLO as {cfg['ehlo']}\n"))
    else:
        print(hdr(f"\nSENDING {len(batch)} test email(s) to {camp['inbox']} "
                  f"via {relay}:25 (EHLO {cfg['ehlo']})"))
        print(dim("  randomized order, natural pacing. Ctrl-C aborts.\n"))

    rows = []
    try:
        for i, domain in enumerate(batch, 1):
            msg, from_addr = build_message(camp, domain)
            if dry:
                safe = domain.replace(".", "_")
                with open(f"{outdir}/{i:02d}-{safe}.eml", "w") as f:
                    f.write(msg.as_string())
                print(f"[{i}/{len(batch)}] {domain}: PREVIEW {outdir}/{i:02d}-{safe}.eml  "
                      f"(From: {from_addr})")
                rows.append([domain, from_addr, camp["inbox"], msg["Subject"], "DRY-RUN", ""])
                continue
            try:
                s = smtplib.SMTP(timeout=25)
                s.connect(relay, 25)
                s.ehlo(cfg["ehlo"])
                s.sendmail(from_addr, [camp["inbox"]], msg.as_string())
                s.quit()
                print(good(f"[{i}/{len(batch)}] {domain}: SENT as {from_addr}"))
                rows.append([domain, from_addr, camp["inbox"], msg["Subject"], "SENT", ""])
            except Exception as e:
                print(bad(f"[{i}/{len(batch)}] {domain}: FAILED {type(e).__name__}: {e}"))
                rows.append([domain, from_addr, camp["inbox"], msg["Subject"],
                             "FAILED", f"{type(e).__name__}: {e}"])
            if i < len(batch) and not dry:
                time.sleep(random.uniform(camp["delay_min"], camp["delay_max"]))
    except KeyboardInterrupt:
        print(warn("\naborted by user — partial results logged"))

    with open(log_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain", "from", "to", "subject", "status", "error"])
        w.writerows(rows)
    print(good(f"\nlog written: {log_path}"))
    if not dry:
        print(warn("Now check the inbox vs spam for each sender address above."))
        print(warn("Inbox (not spam) = that domain's spoof defense FAILED for real."))
    pause()

def show_history():
    logs = sorted(f for f in os.listdir(".") if f.startswith("send-log-") and f.endswith(".csv"))
    if not logs:
        print(dim("\nno send logs yet (send-log-*.csv)"))
        pause()
        return
    print(hdr("\n-- SEND HISTORY --"))
    for i, f in enumerate(logs, 1):
        print(f"  {i}) {f}")
    pick = ask("view which (number, blank=latest)", str(len(logs)))
    if not pick.isdigit() or not (1 <= int(pick) <= len(logs)):
        return
    with open(logs[int(pick) - 1]) as f:
        rows = list(csv.reader(f))[1:]
    print(f"\n{'DOMAIN':36} {'FROM':40} STATUS")
    print("-" * 100)
    for r in rows:
        mark = good(r[4]) if r[4] in ("SENT", "DRY-RUN") else bad(r[4])
        print(f"{r[0]:36} {r[1]:40} {mark} {r[5]}")
    pause()

# ------------------------------------------------------------------ settings
def settings_menu(cfg):
    while True:
        print(hdr("\n-- SETTINGS --  (blank keeps current)"))
        print(dim(f"  config file: {CONFIG_PATH}"))
        cfg["inbox"] = ask("Test inbox (recipient)", cfg["inbox"])
        cfg["from_local"] = ask("From local-part", cfg["from_local"])
        cfg["ehlo"] = ask("EHLO hostname (must match VPS rDNS/PTR)", cfg["ehlo"])
        cfg["mailer"] = ask("X-Mailer", cfg["mailer"])
        cfg["delay_min"] = ask_int("Delay min (s)", cfg["delay_min"], 0, 600)
        cfg["delay_max"] = ask_int("Delay max (s)", cfg["delay_max"], 0, 600)
        cfg["limit"] = ask_int("Default batch cap", cfg["limit"], 1, 200)
        cfg["display_from_domain"] = ask("display-name test sending domain",
                                         cfg.get("display_from_domain", "example.com"))
        save_config(cfg)
        if ask("\nsave & back to menu? [Y/n]", "y").lower().startswith("y"):
            return

# ------------------------------------------------------------------ main flow
def flow_audit(cfg):
    print(hdr("\n-- STEP 1: DOMAIN LIST --"))
    print(dim("  path to a .txt file (one domain per line), or paste/typed list "
              "(spaces or commas). empty line finishes a paste.\n"))
    while True:
        raw = ask("domain file or list")
        if not raw:
            print(bad("  need a file path or at least one domain"))
            continue
        if raw.lower().endswith((".txt", ".csv")) and not os.path.isfile(raw):
            print(bad(f"  file not found: {raw}  (check the path)"))
            continue
        if os.path.isfile(raw):
            with open(raw) as f:
                text = f.read()
            break
        if any(ch in raw for ch in (",", " ", ".")):
            text = raw
            if "." not in text or not parse_domains(text):
                print(bad("  that does not look like a file or a domain list"))
                continue
            break
        print(bad("  not a file, and not a recognizable list"))
    domains = parse_domains(text)
    if not domains:
        print(bad("no usable domains found"))
        pause()
        return
    print(dim(f"parsed {len(domains)} unique domain(s)"))
    results = run_audit(domains)
    save_results(results)
    chosen = select_domains(results)
    if not chosen:
        print(dim("nothing selected — back to menu"))
        pause()
        return
    camp = compose(cfg, chosen)
    action = review(cfg, camp, chosen)
    if action == "e":
        camp = compose(cfg, chosen)
        action = review(cfg, camp, chosen)
    if action == "c":
        print(dim("cancelled — back to menu"))
        pause()
        return
    send_campaign(cfg, camp, chosen, dry=(action == "d"))

def flow_quick(cfg):
    if not os.path.isfile("spoofable.txt"):
        print(bad("\nno spoofable.txt here — run the audit first (menu option 1)"))
        pause()
        return
    with open("spoofable.txt") as f:
        domains = [l.strip() for l in f if l.strip()]
    if not domains:
        print(bad("\nspoofable.txt is empty"))
        pause()
        return
    print(dim(f"loaded {len(domains)} spoofable domain(s) from spoofable.txt"))
    camp = compose(cfg, domains)
    action = review(cfg, camp, domains)
    if action == "e":
        camp = compose(cfg, domains)
        action = review(cfg, camp, domains)
    if action == "c":
        print(dim("cancelled — back to menu"))
        pause()
        return
    send_campaign(cfg, camp, domains, dry=(action == "d"))

def menu():
    cfg = load_config()
    while True:
        banner()
        print(f"  inbox: {cfg['inbox']}   EHLO: {cfg['ehlo']}   "
              f"pacing: {cfg['delay_min']}-{cfg['delay_max']}s   cwd: {os.getcwd()}\n")
        print("  [1] Full audit  — domain list -> ranked results -> select -> compose -> send/dry-run")
        print("  [2] Quick send  — reuse existing spoofable.txt -> compose -> send/dry-run")
        print("  [3] Settings    — inbox / EHLO / mailer / pacing / batch cap / display mode")
        print("  [4] History     — past send logs")
        print("  [5] Audit only  — passive DNS sweep, nothing sent (results -> history)")
        print("  [6] Trend       — per-domain verdict history (JSONL)")
        print("  [q] Quit\n")
        a = ask("choice").lower()
        if a == "1":
            flow_audit(cfg)
        elif a == "2":
            flow_quick(cfg)
        elif a == "3":
            settings_menu(cfg)
        elif a == "4":
            show_history()
        elif a == "5":
            flow_audit_only(cfg)
        elif a == "6":
            show_trend()
        elif a == "q":
            print("bye.")
            return
        else:
            print(bad("  pick 1-6 or q"))

if __name__ == "__main__":
    # headless mode: python3 postcard.py --audit "dom1 dom2 ..." | --audit-file list.txt
    # exit code = highest severity found (0=OK ... 4=CRITICAL) for cron alerting
    args = sys.argv[1:]
    if args and args[0] in ("--audit", "--audit-file"):
        if args[0] == "--audit":
            domains = parse_domains(" ".join(args[1:]))
        else:
            with open(args[1]) as f:
                domains = parse_domains(f.read())
        if not domains:
            print("no usable domains")
            sys.exit(1)
        results = run_audit(domains)
        save_results(results)
        sys.exit(max(r["sev"] for r in results))
    try:
        menu()
    except KeyboardInterrupt:
        print("\ninterrupted — bye.")
        sys.exit(130)
