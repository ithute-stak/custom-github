FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

ENV CUSTOM_GITHUB_DATA_DIR=/data
ENV CUSTOM_GITHUB_WORKSPACE_ROOT=/data/workspaces

VOLUME ["/data"]
EXPOSE 8787

CMD ["uvicorn", "app.platform:app", "--host", "0.0.0.0", "--port", "8787"]
