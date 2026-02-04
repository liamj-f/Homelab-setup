FROM python:3.11-slim

LABEL maintainer="LJF Cloud"
LABEL description="Automatically updates OCI Security List with dynamic IP"

# Install dependencies
RUN pip install --no-cache-dir oci-cli

# Create app directory
WORKDIR /app

# Copy the update script
COPY update_security_list.py /app/

# Make script executable
RUN chmod +x /app/update_security_list.py

# Run the script
CMD ["python", "-u", "/app/update_security_list.py"]
