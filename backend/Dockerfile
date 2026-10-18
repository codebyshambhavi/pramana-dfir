# Build context is the repo root (see docker-compose.yml)
FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
COPY evidence-engine/requirements.txt evidence-engine/requirements.txt
COPY intelligence/requirements.txt intelligence/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt -r evidence-engine/requirements.txt -r intelligence/requirements.txt
COPY contracts contracts
COPY evidence-engine evidence-engine
COPY intelligence intelligence
COPY backend backend
WORKDIR /app/backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
