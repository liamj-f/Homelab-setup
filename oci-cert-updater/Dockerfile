FROM python:3.11-slim

LABEL maintainer="LJF Cloud"
LABEL description="Uploads renewed NPM certificates to OCI Certificates Service"

RUN pip install --no-cache-dir oci-python-sdk

WORKDIR /app

COPY update_certificate.py /app/

RUN chmod +x /app/update_certificate.py

CMD ["python", "-u", "/app/update_certificate.py"]
