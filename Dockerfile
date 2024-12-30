# Use the official Python image
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    tesseract-ocr \
    libtesseract-dev \
    libleptonica-dev \
    pkg-config \
    poppler-utils \
    libjpeg-dev \
    zlib1g-dev \
    libpng-dev \
    libfreetype6-dev \
    liblcms2-dev \
    libopenjp2-7 \
    libtiff5 \
    libwebp-dev \
    tcl8.6-dev \
    tk8.6-dev \
    python3-tk \
    ghostscript \
    # Other dependencies as needed
    && rm -rf /var/lib/apt/lists/*


# Set the working directory
WORKDIR /app

# Copy the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
COPY . .

# Expose the necessary port
EXPOSE 5000

# Command to run your application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
