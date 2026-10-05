FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY sentinelapi ./sentinelapi
RUN pip install --no-cache-dir . && useradd -m scanner
USER scanner
ENTRYPOINT ["sentinelapi"]
