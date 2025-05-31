# Integration Tests

This directory contains integration tests for the proxy server implementation. The tests verify that the proxy server correctly handles different proxy protocols (SOCKS5, SOCKS4, HTTP, HTTPS, SOCKS4a) using Docker containers.

## Prerequisites

- Docker
- Docker Compose
- Rust and Cargo

## Running the Tests

1. Start the test environment:
```bash
cd tests/integration
docker-compose up -d
```

2. Wait for the services to be ready (about 5 seconds)

3. Run the tests:
```bash
cargo test --test proxy_tests -- --nocapture
```

4. Clean up:
```bash
docker-compose down
```

## Test Environment

The test environment consists of:

- SOCKS5 proxy server (port 1080)
- SOCKS4 proxy server (port 1081)
- HTTP/HTTPS proxy server (port 8888)
- Test target server (port 8080)

All proxy servers are configured with the following credentials:
- Username: testuser
- Password: testpass

## Test Cases

The tests verify:
1. SOCKS5 proxy functionality
2. SOCKS4 proxy functionality
3. HTTP proxy functionality
4. HTTPS proxy functionality
5. SOCKS4a proxy functionality

Each test makes a request through the respective proxy to the test target server and verifies that the response is received correctly. 