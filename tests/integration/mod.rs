use std::time::Duration;
use tokio::time::sleep;
use reqwest::{Client, Proxy as ReqwestProxy};
use std::error::Error;

const TEST_USER: &str = "testuser";
const TEST_PASS: &str = "testpass";
const TARGET_HOST: &str = "104.18.26.120:80"; // For SOCKS proxies
const TARGET_URL: &str = "http://example.com"; // For HTTP proxies
const HTTPS_TEST_URL: &str = "https://httpbin.org/get"; // TODO: change to a local server

async fn wait_for_services() {
    // Wait for services to be ready
    sleep(Duration::from_secs(10)).await;
}

// SOCKS5 with auth
#[tokio::test]
async fn test_socks5_proxy_auth() -> Result<(), Box<dyn Error>> {
    wait_for_services().await;
    let proxy = ReqwestProxy::all("socks5://testuser:testpass@localhost:1080")?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("Testing SOCKS5 with auth...");
    let response = client.get(format!("http://{}", TARGET_HOST)).send().await?;
    println!("SOCKS5 auth response status: {}", response.status());
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));
    Ok(())
}

// SOCKS5 without auth
#[tokio::test]
async fn test_socks5_proxy_noauth() -> Result<(), Box<dyn Error>> {
    wait_for_services().await;
    let proxy = ReqwestProxy::all("socks5://localhost:1082")?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("Testing SOCKS5 without auth...");
    let response = client.get(format!("http://{}", TARGET_HOST)).send().await?;
    println!("SOCKS5 noauth response status: {}", response.status());
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));
    Ok(())
}

// SOCKS4 with auth
#[tokio::test]
async fn test_socks4_proxy_auth() -> Result<(), Box<dyn Error>> {
    wait_for_services().await;
    let proxy = ReqwestProxy::all("socks4://testuser:testpass@localhost:1081")?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("Testing SOCKS4 with auth...");
    let response = client.get(format!("http://{}", TARGET_HOST)).send().await?;
    println!("SOCKS4 auth response status: {}", response.status());
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));
    Ok(())
}

// SOCKS4 without auth
#[tokio::test]
async fn test_socks4_proxy_noauth() -> Result<(), Box<dyn Error>> {
    wait_for_services().await;
    let proxy = ReqwestProxy::all("socks4://localhost:1083")?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("Testing SOCKS4 without auth...");
    let response = client.get(format!("http://{}", TARGET_HOST)).send().await?;
    println!("SOCKS4 noauth response status: {}", response.status());
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));
    Ok(())
}

// HTTP proxy without auth
#[tokio::test]
async fn test_http_proxy_noauth() -> Result<(), Box<dyn Error>> {
    wait_for_services().await;
    let proxy = ReqwestProxy::all("http://localhost:8889")?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("Testing HTTP without auth...");
    let response = client.get(TARGET_URL).send().await?;
    println!("HTTP noauth response status: {}", response.status());
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));
    Ok(())
}

// HTTP proxy with auth
#[tokio::test]
async fn test_http_proxy_auth() -> Result<(), Box<dyn Error>> {
    wait_for_services().await;
    let proxy = ReqwestProxy::all(format!("http://{}:{}@localhost:8888", TEST_USER, TEST_PASS))?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    println!("Testing HTTP with auth...");
    let response = client.get(TARGET_URL).send().await?;
    println!("HTTP auth response status: {}", response.status());
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));
    Ok(())
}

// HTTPS proxy test
#[tokio::test]
async fn test_https_proxy() -> Result<(), Box<dyn Error>> {
    wait_for_services().await;
    let proxy = ReqwestProxy::all(format!("http://{}:{}@localhost:8888", TEST_USER, TEST_PASS))?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;

    println!("Testing HTTPS proxy...");
    let response = client.get(HTTPS_TEST_URL).send().await?;
    println!("HTTPS proxy response status: {}", response.status());
    assert!(response.status().is_success());
    Ok(())
}

#[tokio::test]
async fn test_socks4a_proxy() -> Result<(), Box<dyn Error>> {
    wait_for_services().await;

    let proxy = ReqwestProxy::all("socks4a://localhost:1081")?;
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(10))
        .build()?;

    let response = client.get(format!("http://{}", TARGET_HOST)).send().await?;
    assert!(response.status().is_success());
    let body = response.text().await?;
    assert!(body.contains("Test Page"));

    Ok(())
} 