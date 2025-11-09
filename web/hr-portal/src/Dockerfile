# Use a lightweight Python base image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies, including gunicorn
RUN pip install --no-cache-dir flask requests gunicorn

# Copy project files into container
COPY . /app/

# Expose port 5000
EXPOSE 5000

# Run the Flask app with Gunicorn
# -w 4 : 4 workers
# -b 0.0.0.0:5000 : bind to all interfaces inside container
CMD ["gunicorn", "--access-logfile", "-", "--error-logfile", "-", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
