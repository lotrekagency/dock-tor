#!/usr/bin/env bash
set -euo pipefail

: "${CRON_SCHEDULE:=* * * * *}" # default: every minute

# Helper to print key/value with masking for secrets
print_kv() {
	local key="$1"; shift || true
	local val="${1:-}"
	printf "  %-18s = %s\n" "$key" "$val"
}

mask_secret() {
	local v="$1"
	if [[ -z "$v" ]]; then
		echo "(empty)"
	else
		local len=${#v}
		if (( len <= 4 )); then
			printf '%*s\n' "$len" '' | tr ' ' '*'
		else
			# show first/last char only
			echo "${v:0:1}***${v: -1} (len=$len)"
		fi
	fi
}

echo "======================================="
echo "[dock-tor] Container startup"
echo "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "======================================="
print_kv CRON_SCHEDULE        "$CRON_SCHEDULE"
print_kv SMTP_HOST            "$SMTP_HOST"
print_kv SMTP_PORT            "$SMTP_PORT"
print_kv SMTP_USER            "$SMTP_USER"
print_kv SMTP_PASS            "$(mask_secret "$SMTP_PASS")"
print_kv MAIL_FROM            "$MAIL_FROM"
print_kv MAIL_TO              "$MAIL_TO"
print_kv SCAN_SCOPE           "$SCAN_SCOPE"
echo "======================================="

touch /var/log/cron.log


###############################################################################
# Cron environment preparation
# NOTE: The cron daemon does NOT automatically inherit all container env vars.
# We explicitly write the required variables into the crontab file.
###############################################################################

# List of variables we want to propagate to the cron job
CRON_EXPORT_VARS=(
	HOSTNAME SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS SMTP_USE_SSL
	MAIL_FROM MAIL_TO SCAN_SCOPE
	TRIVY_ARGS TRIVY_GITHUB_TOKEN TRIVY_BIN
	EXCLUDE_LABEL ONLY_RUNNING ATTACH_JSON
	MIN_NOTIFY_SEVERITY LOG_LEVEL
)

CRON_FILE=/etc/cron.d/scanner
{
	echo "SHELL=/bin/bash"
	echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for v in "${CRON_EXPORT_VARS[@]}"; do
		if [[ -n "${!v-}" ]]; then
			safe_value=${!v//%/%%}
			echo "$v=$safe_value"
		fi
	done
	echo "$CRON_SCHEDULE /usr/local/bin/python /app/main.py >> /var/log/cron.log 2>&1"
} > "$CRON_FILE"

chmod 0644 "$CRON_FILE"
crontab "$CRON_FILE"

echo "[dock-tor] Installed cron job: $CRON_SCHEDULE"

tail -F /var/log/cron.log &
TAIL_PID=$!

cleanup() {
	echo "[dock-tor] Caught signal, terminating (tail pid=$TAIL_PID)." >&2
	kill "$TAIL_PID" 2>/dev/null || true
	exit 0
}

trap cleanup INT TERM

exec cron -f