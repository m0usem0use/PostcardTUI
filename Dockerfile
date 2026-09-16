# PostcardTUI — SPF/DMARC spoofability audit & authorized-domain test sender
#
# Build:   docker build -t postcardtui .
# Audit (passive DNS only, safe for any domain):
#   docker run --rm -v "$PWD":/data postcardtui --audit "example.com test.domain"
#   docker run --rm -v "$PWD":/data postcardtui --audit-file /data/domains.txt
# Interactive wizard (sends require explicit review inside the wizard):
#   docker run --rm -it -v "$PWD":/data postcardtui
#
# Ethics: audit mode is DNS-only. SEND mode dispatches real spoof-test
# emails — run it ONLY against domains you own or are authorized to test
# (see ETHICS.md). The exit code of --audit equals the worst severity
# found (0=OK .. 4=CRITICAL), so it drops straight into CI/cron.

FROM python:3.12-alpine

# No third-party deps by design — stdlib only (smtplib, urllib, json, csv).
# DoH goes to dns.google over HTTPS; nothing else leaves the container in
# audit mode.

WORKDIR /data
COPY postcard_tui.py /app/postcard_tui.py

# Reports / history / send-logs land in the mounted volume, not in the image.
ENV PYTHONUNBUFFERED=1 \
    POSTCARD_HOME=/data

ENTRYPOINT ["python3", "/app/postcard_tui.py"]
# Default arg = interactive wizard. Headless: append --audit "dom1 dom2".
