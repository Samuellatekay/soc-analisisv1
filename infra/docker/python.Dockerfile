FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "psycopg[binary]"
COPY services ./services
COPY apps/api ./apps/api
COPY apps/master ./apps/master
COPY infra/config ./infra/config
COPY data ./data
ENV PYTHONPATH=/app:/app/apps/api
RUN useradd -m soc && mkdir -p /app/data /backups && chown -R soc /app /backups
USER soc
# CMD ditentukan per layanan di docker-compose
