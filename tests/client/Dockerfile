FROM python:3.14-slim
WORKDIR /probe
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY probe.py .
ENTRYPOINT ["python", "probe.py"]
