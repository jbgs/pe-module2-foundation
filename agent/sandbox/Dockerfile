# The sandbox image: a clean, defined environment for one run of the scripted agent.
# The limits are not in this file: they are set when the container is started (see agent/run_agent.py), because
# the platform that runs an agent must not depend on the agent's own image to restrict it.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# An unprivileged user with no home directory and no login shell.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin --uid 10001 agent

COPY actions.py /sandbox/actions.py

USER 10001
WORKDIR /workspace
ENTRYPOINT ["python", "/sandbox/actions.py"]
