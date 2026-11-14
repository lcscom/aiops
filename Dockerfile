FROM python:3.12-slim
WORKDIR /opt/aiops
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN python -m compileall -q app
ENV AIOPS_CONFIG=/opt/aiops/config.yaml PYTHONUNBUFFERED=1
EXPOSE 8630 514/udp 514/tcp 6514/tcp 162/udp
CMD ["python", "-m", "app.serve"]
