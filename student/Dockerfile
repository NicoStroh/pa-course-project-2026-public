FROM python:3.13-slim

WORKDIR /workspace

RUN apt-get update \
	&& apt-get install -y --no-install-recommends gnupg tar \
	&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt /workspace/requirements.txt
RUN pip install --no-cache-dir -r /workspace/requirements.txt

COPY analyzer /workspace/analyzer
COPY analyze /usr/local/bin/analyze
RUN chmod +x /usr/local/bin/analyze

ENTRYPOINT ["analyze"]
