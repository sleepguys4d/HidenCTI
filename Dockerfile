FROM python:3.12-slim

LABEL org.opencontainers.image.title="HIDEN by SEC4DATA"
LABEL org.opencontainers.image.description="Threat Hunting, OSINT & CTI platform (defensive)"
LABEL org.opencontainers.image.vendor="SEC4DATA · Luanda · Angola"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

RUN apt-get update && apt-get install -y --no-install-recommends \
      libfreetype6 libjpeg62-turbo \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
RUN mkdir -p /srv/data /srv/reports

EXPOSE 8000

RUN useradd -m -u 10001 hunter && chown -R hunter:hunter /srv
USER hunter

HEALTHCHECK --interval=30s --timeout=4s --start-period=8s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
