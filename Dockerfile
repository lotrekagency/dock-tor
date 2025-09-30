FROM python:3.12-slim

# Install cron & curl for Trivy install
RUN apt-get update && apt-get install -y --no-install-recommends \
    cron curl ca-certificates gnupg && \
    rm -rf /var/lib/apt/lists/*

# Install Trivy (official install script)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin


# Install Python deps
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# App
WORKDIR /app
COPY app/ /app/
RUN chmod +x /app/entrypoint.sh

ENV CRON_SCHEDULE="0 * * * *" \
    ONLY_RUNNING="true" \
    ATTACH_JSON="true" \
    TRIVY_ARGS="--severity HIGH,CRITICAL --ignore-unfixed --timeout 5m" \
    EXCLUDE_LABEL="docktor.ignore=true"

ENV TRIVY_CACHE_DIR=/home/scanner/.cache/trivy

ENTRYPOINT ["/app/entrypoint.sh"]