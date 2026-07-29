use tokio::io::{AsyncWriteExt, DuplexStream};
use varmlen_protocol::{ServiceErrorCode, MAX_FRAME_BYTES};
use varmlen_service_core::framing::{read_payload, write_payload};

#[tokio::test]
async fn rejects_length_prefix_above_limit_without_waiting_for_a_body() {
    let (mut client, mut server) = tokio::io::duplex(16);
    client
        .write_u32((MAX_FRAME_BYTES + 1) as u32)
        .await
        .unwrap();

    assert_eq!(
        read_payload(&mut server).await,
        Err(ServiceErrorCode::FrameTooLarge)
    );
}

#[tokio::test]
async fn framed_payload_round_trip_preserves_bytes() {
    let (mut client, mut server): (DuplexStream, DuplexStream) = tokio::io::duplex(64);
    let expected = br#"{"operation_id":42}"#.to_vec();
    let to_write = expected.clone();

    let writer = tokio::spawn(async move {
        write_payload(&mut client, &to_write).await.unwrap();
    });

    assert_eq!(read_payload(&mut server).await.unwrap(), expected);
    writer.await.unwrap();
}

#[tokio::test]
async fn refuses_to_write_a_payload_above_the_protocol_limit() {
    let mut sink = tokio::io::sink();
    let payload = vec![0; MAX_FRAME_BYTES + 1];

    assert_eq!(
        write_payload(&mut sink, &payload).await,
        Err(ServiceErrorCode::FrameTooLarge)
    );
}
