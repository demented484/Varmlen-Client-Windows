use std::path::PathBuf;

use varmlen_protocol::{
    AppSelector, ConnectRequest, RequestEnvelope, ServiceCommand, PROTOCOL_VERSION,
};
use varmlen_service::{
    process_plan::{
        retry_address_not_ready, socks5_ipv4_connect_request, validate_socks5_connect_header,
        validate_socks5_method_reply, XrayConfigTransaction, XrayInvocation, XrayInvocationKind,
    },
    state_record::{
        decode_desired_state, encode_desired_state, DesiredStatePhase, DesiredStateRecord,
    },
};

#[tokio::test]
async fn transient_windows_address_not_ready_is_retried_before_tun_probe() {
    let mut attempts = 0;
    let value = retry_address_not_ready(
        || {
            attempts += 1;
            if attempts < 3 {
                Err(std::io::Error::from_raw_os_error(10049))
            } else {
                Ok("bound")
            }
        },
        4,
        std::time::Duration::ZERO,
    )
    .await
    .expect("eventually bindable TUN address");

    assert_eq!(value, "bound");
    assert_eq!(attempts, 3);
}

#[tokio::test]
async fn permanent_bind_errors_are_not_hidden_by_tun_readiness_retry() {
    let mut attempts = 0;
    let error = retry_address_not_ready(
        || {
            attempts += 1;
            Err::<(), _>(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "denied",
            ))
        },
        4,
        std::time::Duration::ZERO,
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(attempts, 1);
}

fn request() -> ConnectRequest {
    ConnectRequest {
        xray_version: "26.3.27".into(),
        xray_config: r#"{"inbounds":[{"protocol":"tun"}]}"#.into(),
        validation_config: r#"{"inbounds":[{"protocol":"socks"}]}"#.into(),
        server_endpoints: vec!["203.0.113.1:443".parse().expect("socket")],
        excluded_apps: vec![AppSelector {
            canonical_path: r"C:\Games\Counter-Strike 2\game\bin\win64\cs2.exe".into(),
            basename: "cs2.exe".into(),
        }],
        apps_selective: false,
        killswitch: true,
        allow_lan: false,
    }
}

#[test]
fn validation_probe_uses_a_no_auth_socks5_connect_request() {
    assert_eq!(
        socks5_ipv4_connect_request([1, 1, 1, 1], 443),
        [5, 1, 0, 1, 1, 1, 1, 1, 1, 187]
    );
    assert!(validate_socks5_method_reply([5, 0]).is_ok());
    assert!(validate_socks5_method_reply([5, 2]).is_err());
    assert_eq!(
        validate_socks5_connect_header([5, 0, 0, 1]).expect("IPv4 reply"),
        6
    );
    assert_eq!(
        validate_socks5_connect_header([5, 0, 0, 4]).expect("IPv6 reply"),
        18
    );
    assert!(validate_socks5_connect_header([5, 4, 0, 1]).is_err());
}

#[test]
fn xray_invocations_use_fixed_arguments_without_shell_interpolation() {
    let executable = PathBuf::from(r"C:\Program Files\Varmlen\xray.exe");
    let config = PathBuf::from(r"C:\ProgramData\Varmlen\validation.json");
    let validation = XrayInvocation::validation(executable.clone(), config.clone());
    assert_eq!(validation.kind, XrayInvocationKind::Validate);
    assert_eq!(validation.executable, executable);
    assert_eq!(
        validation.arguments,
        vec![
            "run".to_string(),
            "-test".to_string(),
            "-c".to_string(),
            config.to_string_lossy().into_owned()
        ]
    );
    assert!(!validation.arguments.join(" ").contains("cmd.exe"));

    let run = XrayInvocation::run(
        PathBuf::from(r"C:\Program Files\Varmlen\xray.exe"),
        PathBuf::from(r"C:\ProgramData\Varmlen\active.json"),
    );
    assert_eq!(run.kind, XrayInvocationKind::Run);
    assert_eq!(run.arguments[0], "run");
    assert!(!run.arguments.contains(&"-test".to_string()));
}

#[test]
fn native_preflight_and_candidate_start_use_the_same_config_file() {
    let executable = PathBuf::from(r"C:\Program Files\Varmlen\xray.exe");
    let candidate = PathBuf::from(r"C:\ProgramData\Varmlen\candidate.json");
    let active = PathBuf::from(r"C:\ProgramData\Varmlen\active.json");
    let transaction = XrayConfigTransaction::new(executable, candidate.clone(), active.clone());

    assert_eq!(transaction.preflight().kind, XrayInvocationKind::Validate);
    assert_eq!(transaction.preflight().config_path(), candidate);
    assert_eq!(transaction.start_candidate().kind, XrayInvocationKind::Run);
    assert_eq!(transaction.start_candidate().config_path(), candidate);
    assert_eq!(transaction.active_path(), active.as_path());
    assert_ne!(transaction.start_candidate().config_path(), active);
}

#[test]
fn desired_state_round_trip_preserves_operation_and_policy() {
    let candidate = request();
    let mut previous = request();
    previous.allow_lan = true;
    let record = DesiredStateRecord::connecting(
        918,
        candidate.clone(),
        Some(previous.clone()),
        candidate.killswitch,
    );
    let bytes = encode_desired_state(&record).expect("encode");
    let decoded = decode_desired_state(&bytes).expect("decode");
    assert_eq!(decoded, record);
    assert_eq!(
        decoded.phase,
        DesiredStatePhase::Connecting {
            candidate,
            previous: Some(previous),
            requested_kill_switch: true,
        }
    );
}

#[test]
fn desired_state_rejects_unknown_versions_and_trailing_data() {
    let mut record = DesiredStateRecord::connected(1, request());
    record.format_version = DesiredStateRecord::FORMAT_VERSION + 1;
    assert!(encode_desired_state(&record).is_err());

    record.format_version = DesiredStateRecord::FORMAT_VERSION;
    let mut bytes = encode_desired_state(&record).expect("encode");
    bytes.extend_from_slice(b"secret trailing material");
    assert!(decode_desired_state(&bytes).is_err());
}

#[test]
fn journal_has_explicit_safe_terminal_states() {
    let disconnected = DesiredStateRecord::disconnected(5);
    assert_eq!(disconnected.phase, DesiredStatePhase::Disconnected);

    let blocked = DesiredStateRecord::blocked(6, "candidate failed");
    assert_eq!(
        blocked.phase,
        DesiredStatePhase::Blocked {
            reason: "candidate failed".into()
        }
    );

    let disconnecting = DesiredStateRecord::disconnecting(7, true);
    assert_eq!(
        disconnecting.phase,
        DesiredStatePhase::Disconnecting { keep_blocked: true }
    );
}

#[test]
fn version_one_connected_state_is_migrated_to_the_journal() {
    let request = request();
    let payload = serde_json::to_vec(&serde_json::json!({
        "format_version": 1,
        "operation_id": 81,
        "request": request,
    }))
    .expect("legacy payload");
    let mut encoded = b"VRMLNST1".to_vec();
    encoded.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    encoded.extend_from_slice(&payload);

    let migrated = decode_desired_state(&encoded).expect("migrate v1");
    assert_eq!(migrated.format_version, DesiredStateRecord::FORMAT_VERSION);
    assert!(matches!(
        migrated.phase,
        DesiredStatePhase::Connected { .. }
    ));
}

#[test]
fn protocol_envelope_can_carry_the_persisted_request_without_shape_changes() {
    let request = request();
    let envelope = RequestEnvelope {
        version: PROTOCOL_VERSION,
        operation_id: 44,
        command: ServiceCommand::Connect(request.clone()),
    };
    let encoded = serde_json::to_vec(&envelope).expect("protocol JSON");
    let decoded: RequestEnvelope = serde_json::from_slice(&encoded).expect("decode protocol");
    assert_eq!(decoded.command, ServiceCommand::Connect(request));
}
