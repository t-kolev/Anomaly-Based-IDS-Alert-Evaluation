#!/bin/bash
# run.sh

# Step 1: Build the Docker image
docker build -t feature-extraction .

# Step 2: Run the Docker container
docker run --rm -v $(pwd)/dataset:/app/dataset -v $(pwd)/zeek_logs:/app/zeek_logs feature-extraction
