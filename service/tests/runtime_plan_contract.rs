use std::path::PathBuf;

use varmlen_protocol::{
    AppSelector, ConnectRequest, RequestEnvelope, ServiceCommand, PROTOCOL_VERSION,
};
use varmlen_service::{
    process_plan::{
        socks5_ipv4_connect_request, validate_socks5_connect_header, validate_socks5_method_reply,
        XrayInvocation, XrayInvocationKind,
    },
    state_record::{decode_desired_state, encode_desired_state, DesiredStateRecord},
};

fn request() -> ConnectRequest {
    ConnectRequest {
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
fn desired_state_round_trip_preserves_operation_and_policy() {
    let record = DesiredStateRecord {
        format_version: DesiredStateRecord::FORMAT_VERSION,
        operation_id: 918,
        request: request(),
    };
    let bytes = encode_desired_state(&record).expect("encode");
    let decoded = decode_desired_state(&bytes).expect("decode");
    assert_eq!(decoded, record);
}

#[test]
fn desired_state_rejects_unknown_versions_and_trailing_data() {
    let mut record = DesiredStateRecord {
        format_version: DesiredStateRecord::FORMAT_VERSION + 1,
        operation_id: 1,
        request: request(),
    };
    assert!(encode_desired_state(&record).is_err());

    record.format_version = DesiredStateRecord::FORMAT_VERSION;
    let mut bytes = encode_desired_state(&record).expect("encode");
    bytes.extend_from_slice(b"secret trailing material");
    assert!(decode_desired_state(&bytes).is_err());
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
