//! Integration tests against the docker-compose stack in this directory.
//!
//! These tests are **opt-in**. By default they return immediately without touching
//! the network or sleeping. To run them:
//!
//! ```sh
//! cd tests/integration && docker-compose up -d
//! RUN_PURROUTE_INTEGRATION=1 cargo test -p purroute --test integration -- --nocapture
//! ```
//!
//! When `RUN_PURROUTE_INTEGRATION` is unset, each test skips instantly.
//! When it is `1`, the stack must be up (SOCKS5 on `127.0.0.1:1080`) or the test **fails**.

use reqwest::{Client, Proxy as ReqwestProxy};
use std::error::Error;
use std::time::Duration;
use tokio::time::sleep;

const TEST_USER: &str = "testuser";
const TEST_PASS: &str = "testpass";

fn integration_enabled() -> bool {
    std::env::var("RUN_PURROUTE_INTEGRATION")
        .ok()
        .as_deref()
        == Some("1")
}

fn integration_stack_ready() -> bool {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;
    let addr: SocketAddr = "127.0.0.1:1080".parse().expect("addr");
    TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok()
}

/// Gate integration tests: skip when opt-in env is unset; fail when opt-in but stack down.
fn require_integration() -> bool {
    if !integration_enabled() {
        eprintln!("integration: skipped (set RUN_PURROUTE_INTEGRATION=1 to run)");
        return false;
    }
    if !integration_stack_ready() {
        panic!(
            "integration: RUN_PURROUTE_INTEGRATION=1 but nothing on :1080 — \
             start tests/integration/docker-compose.yml"
        );
    }
    true
}

// Hermetic targets: default to the local `target:8080` container from
// tests/integration/docker-compose.yml. Override with TEST_TARGET_* env vars to
// point at a different endpoint.
//
// `target_host()` is a host:port used to build `http://{target_host()}` for SOCKS
// tests; `target_url()` is a full URL for HTTP-proxy tests; `https_test_url()` is a
// full https URL for the CONNECT tunnel test.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}
fn target_host() -> String {
    env_or("TEST_TARGET_HOST", "127.0.0.1:8080")
}
fn target_url() -> String {
    env_or("TEST_TARGET_URL", "http://127.0.0.1:8080")
}
fn https_test_url() -> String {
    env_or("TEST_TARGET_HTTPS_URL", "https://127.0.0.1:8080")
}

async fn wait_for_services() {
    // Port probe in `require_integration` already confirmed :1080; brief settle only.
    sleep(Duration::from_millis(500)).await;
}

// SOCKS5 with auth
#[tokio::test]
async fn test_socks5_proxy_auth() -> Result<(), Box<dyn Error>> {
    if !require_integration() {
        return Ok(());
    }
    wait_for_services().await;
    let proxy = ReqwestProxy::all("socks5://testuser:testpass@localhost:1080")?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("Testing SOCKS5 with auth...");
    let response = client
        .get(format!("http://{}", target_host()))
        .send()
        .await?;
    println!("SOCKS5 auth response status: {}", response.status());
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));
    Ok(())
}

// SOCKS5 without auth
#[tokio::test]
async fn test_socks5_proxy_noauth() -> Result<(), Box<dyn Error>> {
    if !require_integration() {
        return Ok(());
    }
    wait_for_services().await;
    let proxy = ReqwestProxy::all("socks5://localhost:1082")?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("Testing SOCKS5 without auth...");
    let response = client
        .get(format!("http://{}", target_host()))
        .send()
        .await?;
    println!("SOCKS5 noauth response status: {}", response.status());
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));
    Ok(())
}

// SOCKS4 with auth
#[tokio::test]
async fn test_socks4_proxy_auth() -> Result<(), Box<dyn Error>> {
    if !require_integration() {
        return Ok(());
    }
    wait_for_services().await;
    let proxy = ReqwestProxy::all("socks4://testuser:testpass@localhost:1081")?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("Testing SOCKS4 with auth...");
    let response = client
        .get(format!("http://{}", target_host()))
        .send()
        .await?;
    println!("SOCKS4 auth response status: {}", response.status());
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));
    Ok(())
}

// SOCKS4 without auth
#[tokio::test]
async fn test_socks4_proxy_noauth() -> Result<(), Box<dyn Error>> {
    if !require_integration() {
        return Ok(());
    }
    wait_for_services().await;
    let proxy = ReqwestProxy::all("socks4://localhost:1083")?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("Testing SOCKS4 without auth...");
    let response = client
        .get(format!("http://{}", target_host()))
        .send()
        .await?;
    println!("SOCKS4 noauth response status: {}", response.status());
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));
    Ok(())
}

// HTTP proxy without auth
#[tokio::test]
async fn test_http_proxy_noauth() -> Result<(), Box<dyn Error>> {
    if !require_integration() {
        return Ok(());
    }
    wait_for_services().await;
    let proxy = ReqwestProxy::all("http://localhost:8889")?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("Testing HTTP without auth...");
    let response = client.get(target_url()).send().await?;
    println!("HTTP noauth response status: {}", response.status());
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));
    Ok(())
}

// HTTP proxy with auth
#[tokio::test]
async fn test_http_proxy_auth() -> Result<(), Box<dyn Error>> {
    if !require_integration() {
        return Ok(());
    }
    wait_for_services().await;
    let proxy = ReqwestProxy::all(format!("http://{}:{}@localhost:8888", TEST_USER, TEST_PASS))?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("Testing HTTP with auth...");
    let response = client.get(target_url()).send().await?;
    println!("HTTP auth response status: {}", response.status());
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));
    Ok(())
}

// HTTPS proxy test
#[tokio::test]
async fn test_https_proxy() -> Result<(), Box<dyn Error>> {
    if !require_integration() {
        return Ok(());
    }
    wait_for_services().await;
    let proxy = ReqwestProxy::all(format!("http://{}:{}@localhost:8888", TEST_USER, TEST_PASS))?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;

    println!("Testing HTTPS proxy...");
    let response = client.get(https_test_url()).send().await?;
    println!("HTTPS proxy response status: {}", response.status());
    assert!(response.status().is_success());
    Ok(())
}

#[tokio::test]
async fn test_socks4a_proxy() -> Result<(), Box<dyn Error>> {
    if !require_integration() {
        return Ok(());
    }
    wait_for_services().await;

    let proxy = ReqwestProxy::all("socks4a://localhost:1081")?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    let response = client
        .get(format!("http://{}", target_host()))
        .send()
        .await?;
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));

    Ok(())
}
