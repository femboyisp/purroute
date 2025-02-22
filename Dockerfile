# Dockerfile for PostgreSQL
FROM postgres:13

# Set environment variables for PostgreSQL
ENV POSTGRES_DB=purroute
ENV POSTGRES_USER=purroute_user
ENV POSTGRES_PASSWORD=purroute_password

# Copy the initialization script to the Docker image
COPY init.sql /docker-entrypoint-initdb.d/
