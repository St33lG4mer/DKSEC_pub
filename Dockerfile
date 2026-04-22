FROM python:3.13-slim

RUN pip install --no-cache-dir requests pyyaml && \
    apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY threat_hunter.py .

RUN mkdir -p /data/state /data/reports

VOLUME ["/data/state", "/data/reports", "/data/repo"]

ENTRYPOINT ["python3", "threat_hunter.py", "--config", "/app/config.yaml"]
