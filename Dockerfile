FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and files
COPY src/ ./src/
COPY web/ ./web/
COPY web_app.py cli.py ./

# Expose port 8080
EXPOSE 8080

# Run with gunicorn in production
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "web_app:app"]
