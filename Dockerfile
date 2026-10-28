FROM python:3.12-slim

# Create non-root user
RUN groupadd -r fang && useradd -r -g fang fang

WORKDIR /app

# Copy application and install
COPY . /app
RUN pip install --no-cache-dir .

USER fang

ENTRYPOINT ["fang"]
CMD ["--help"]
