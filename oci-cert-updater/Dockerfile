FROM python:3.13-slim

LABEL maintainer="LJF Cloud"
LABEL description="Uploads renewed NPM certificates to OCI Certificates Service"

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

WORKDIR /app

COPY update_certificate.py /app/

RUN chmod +x /app/update_certificate.py

CMD ["python", "-u", "/app/update_certificate.py"]
