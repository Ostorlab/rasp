FROM python:3.12-slim
WORKDIR /app
COPY verifier /app/verifier
RUN python -m pip install --no-cache-dir /app/verifier \
    && useradd --create-home --uid 10001 rasp
USER rasp
EXPOSE 8080
ENTRYPOINT ["python", "-m", "rasp_verifier.console_server"]
CMD ["--config", "/run/principals.json", "--host", "0.0.0.0", "--port", "8080"]
