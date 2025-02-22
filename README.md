# purroute

### Example Configuration

The `config.toml.example` file provides an example configuration for the proxy server. It includes settings for the router, individual proxy configurations, global proxy settings, proxy chaining, proxy lists, and proxy scraping.

### Docker Setup

The `Dockerfile` and `docker-compose.yml` files are used to set up a PostgreSQL database for storing proxy server statistics. The `init.sql` script initializes the database with the necessary tables.

## Running the Proxy Server

1. **Clone the Repository**:
   ```sh
   git clone https://github.com/FemboyISP/purroute.git
   cd purroute
   ```

2. **Build and Run the Docker Container**:
   ```sh
   docker-compose up --build
   ```

3. **Run the Proxy Server**:
   ```sh
   cargo run --release
   ```

4. **Configuration**:
   - Copy the example configuration file:
     ```sh
     cp config.toml.example config.toml
     ```
   - Edit `config.toml` to suit your needs.

## Features

- **Protocol Support**: Supports HTTP, HTTPS, and SOCKS5 proxy protocols.
- **Authentication**: Supports basic authentication for SOCKS5 and HTTP proxies.
- **Statistics**: Tracks the number of bytes transferred and the number of active connections.
- **Logging**: Logs connection details and errors.
- **Database Integration**: Stores statistics in a PostgreSQL database.
- **Configuration**: Flexible configuration through a TOML file.
