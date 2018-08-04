# Use Python on Alpine Linux as base image
FROM python:alpine

# Create working directory
RUN mkdir -p /app
WORKDIR /app

# Copy requirements.txt to force Docker not to use the cache
COPY requirements.txt /app

# Install app dependencies
RUN pip3 install -r requirements.txt

# Copy app source
COPY . /app

# Define entrypoint of the app
ENTRYPOINT ["python3", "-u", "extractor.py"]
