FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PIP_DISABLE_PIP_VERSION_CHECK=on

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

RUN useradd -m -r django \
    && mkdir -p /app/staticfiles /app/media \
    && chown -R django:django /app

COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

COPY ./service_auth .

USER django

CMD ["/app/entrypoint.sh"]
