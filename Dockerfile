FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    SCAN_PARALLEL=auto

WORKDIR /app

# Fonts so Arabic text shows correctly in the PDFs
RUN apt-get update \
 && apt-get install -y --no-install-recommends fonts-noto-core fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Headless shell only: the scanner never opens a visible browser, and the smaller image starts faster on Render
RUN pip install --no-cache-dir -r requirements.txt \
 && python -m playwright install --with-deps --only-shell chromium

COPY . .

EXPOSE 8000
CMD gunicorn app:app --bind 0.0.0.0:${PORT:-8000} --workers 1 --threads 8 --timeout 120
