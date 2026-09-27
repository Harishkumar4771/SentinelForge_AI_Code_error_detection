FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Let the app know it's running in docker
ENV SENTINELFORGE_SANDBOX_TYPE=docker

CMD ["uvicorn", "app.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
