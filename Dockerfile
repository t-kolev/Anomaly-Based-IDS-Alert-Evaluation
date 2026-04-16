# Dockerfile

# Step 1: Use a Python base image
FROM python:3.9-slim

# Step 2: Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcap-dev \
    wget \
    curl \
    gnupg \
    gcc \
    tshark \
    argus-server \
    argus-client \
    && apt-get clean

# Step 3: Add the Zeek official repository and install Zeek
RUN curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg && \
    echo "deb http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /" > /etc/apt/sources.list.d/zeek.list && \
    apt-get update && apt-get install -y zeek && apt-get clean

# Step 4: Install Python libraries
# Copy requirements file and install Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Step 5: Create a working directory
WORKDIR /app

# Step 6: Copy the necessary files
# Files for the parsing of pcaps
COPY IDS/scripts/pcaps_parsing_script.py /app/pcaps_parsing_script.py
COPY IDS/dataset /app/dataset 

# Files for loading the model
COPY IDS/model/kmeans.pkl /app/model/kmeans.pkl
COPY IDS/model/pipeline.pkl /app/model/pipeline.pkl
COPY IDS/model/Y_train_balanced.pkl /app/model/Y_train_balanced.pkl

# Files for generating alerts
COPY IDS/scripts/generate_alerts.py /app/generate_alerts.py
COPY CaseManagement /app/CaseManagement

# Step 7: Set the PATH to include Zeek's installation directory
ENV PATH="/opt/zeek/bin:$PATH"

