#[cfg(not(windows))]
#[tokio::test]
async fn status_request_does_not_attempt_ipc_outside_windows() {
    assert_eq!(
        varmlen_lib::service_client::service_status()
            .await
            .unwrap_err(),
        "VarmlenService is only supported on Windows"
    );
}
