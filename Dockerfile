FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
ENV PYTHONUNBUFFERED=1
EXPOSE 5000
CMD ["gunicorn", "--preload", "-b", "0.0.0.0:5000", "-w", "2", "--timeout", "300", "app.main:app"]
