# Intentionally insecure Dockerfile for scanner testing. Never deploy.
FROM python:3.8
USER root
ADD . /app
RUN pip install flask==0.12.2
ENV API_TOKEN=changeme
EXPOSE 22
CMD ["python", "/app/app.py"]