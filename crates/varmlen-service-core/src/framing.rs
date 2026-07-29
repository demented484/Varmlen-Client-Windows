use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use varmlen_protocol::{ServiceErrorCode, MAX_FRAME_BYTES};

pub async fn read_payload<R>(reader: &mut R) -> Result<Vec<u8>, ServiceErrorCode>
where
    R: AsyncRead + Unpin,
{
    let length = reader
        .read_u32()
        .await
        .map_err(|_| ServiceErrorCode::InvalidFrame)? as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ServiceErrorCode::FrameTooLarge);
    }

    let mut payload = vec![0; length];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| ServiceErrorCode::InvalidFrame)?;
    Ok(payload)
}

pub async fn write_payload<W>(writer: &mut W, payload: &[u8]) -> Result<(), ServiceErrorCode>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ServiceErrorCode::FrameTooLarge);
    }

    writer
        .write_u32(payload.len() as u32)
        .await
        .map_err(|_| ServiceErrorCode::Internal)?;
    writer
        .write_all(payload)
        .await
        .map_err(|_| ServiceErrorCode::Internal)
}
