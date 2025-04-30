FROM python:3.11-slim

WORKDIR /app

# Install PostgreSQL client and development libraries and C standard library headers
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    libpq-dev \
    gcc \
    libc6-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# Set environment variable to disable bytecode generation
ENV PYTHONDONTWRITEBYTECODE=1
# Ensure Python output is sent straight to terminal
ENV PYTHONUNBUFFERED=1

CMD ["python", "app.py"]