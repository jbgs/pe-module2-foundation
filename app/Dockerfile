# Minimal image for the Module 2 lab service. Built in CI, so no Docker is needed on a laptop.
# The base is pinned by tag for readability; pin by digest once an update policy exists.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Run as an unprivileged user with no home directory and no login shell.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin --uid 10001 app

WORKDIR /app
COPY main.py .

# The pipeline passes the commit SHA, so a running container can always say what it is.
ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}

USER 10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]

CMD ["python", "main.py"]
