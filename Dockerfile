# Dockerfile for PostgreSQL
FROM postgres:13

# Set environment variables for PostgreSQL
ENV POSTGRES_DB=purroute
ENV POSTGRES_USER=purroute
#ENV POSTGRES_PASSWORD=""
ENV POSTGRES_HOST_AUTH_METHOD="trust"
