use varmlen_protocol::{
    decode_request, decode_response, encode_payload, validate_request, AppSelector, ConnectRequest,
    ConnectionPhase, RequestEnvelope, ResponseEnvelope, ServiceCommand, ServiceErrorCode,
    ServiceState, PROTOCOL_VERSION,
};

fn valid_request() -> RequestEnvelope {
    RequestEnvelope {
        version: PROTOCOL_VERSION,
        operation_id: 41,
        command: ServiceCommand::Connect(ConnectRequest {
            xray_config: r#"{"inbounds":[],"outbounds":[]}"#.into(),
            validation_config: r#"{"inbounds":[],"outbounds":[]}"#.into(),
            server_endpoints: vec!["203.0.113.7:443".parse().unwrap()],
            excluded_apps: vec![AppSelector {
                canonical_path: r"C:\Games\Counter-Strike 2\game\bin\win64\cs2.exe".into(),
                basename: "cs2.exe".into(),
            }],
            apps_selective: false,
            killswitch: true,
            allow_lan: false,
        }),
    }
}

#[test]
fn rejects_a_nul_in_an_executable_selector() {
    let mut request = valid_request();
    let ServiceCommand::Connect(connect) = &mut request.command else {
        unreachable!()
    };
    connect.excluded_apps[0].canonical_path.push('\0');
    assert_eq!(
        validate_request(&request),
        Err(ServiceErrorCode::InvalidRequest)
    );
}

#[test]
fn rejects_a_withdrawn_protocol_version() {
    let mut request = valid_request();
    request.version = PROTOCOL_VERSION - 1;
    assert_eq!(
        validate_request(&request),
        Err(ServiceErrorCode::UnsupportedVersion)
    );
}

#[test]
fn rejects_a_connect_request_without_a_server_endpoint() {
    let mut request = valid_request();
    let ServiceCommand::Connect(connect) = &mut request.command else {
        unreachable!()
    };
    connect.server_endpoints.clear();
    assert_eq!(
        validate_request(&request),
        Err(ServiceErrorCode::InvalidRequest)
    );
}

#[test]
fn rejects_an_empty_executable_basename() {
    let mut request = valid_request();
    let ServiceCommand::Connect(connect) = &mut request.command else {
        unreachable!()
    };
    connect.excluded_apps[0].basename.clear();
    assert_eq!(
        validate_request(&request),
        Err(ServiceErrorCode::InvalidRequest)
    );
}

#[test]
fn rejects_more_than_256_excluded_apps() {
    let mut request = valid_request();
    let ServiceCommand::Connect(connect) = &mut request.command else {
        unreachable!()
    };
    let app = connect.excluded_apps[0].clone();
    connect.excluded_apps = vec![app; 257];
    assert_eq!(
        validate_request(&request),
        Err(ServiceErrorCode::InvalidRequest)
    );
}

#[test]
fn oversized_serialized_payload_is_rejected() {
    let payload = "x".repeat(1024 * 1024 + 1);
    assert_eq!(
        encode_payload(&payload),
        Err(ServiceErrorCode::FrameTooLarge)
    );
}

#[test]
fn rejects_empty_or_oversized_xray_configs() {
    for config in [String::new(), "x".repeat(384 * 1024 + 1)] {
        let mut request = valid_request();
        let ServiceCommand::Connect(connect) = &mut request.command else {
            unreachable!()
        };
        connect.xray_config = config;
        assert_eq!(
            validate_request(&request),
            Err(ServiceErrorCode::InvalidRequest)
        );
    }
}

#[test]
fn rejects_empty_or_oversized_validation_configs() {
    for config in [String::new(), "x".repeat(384 * 1024 + 1)] {
        let mut request = valid_request();
        let ServiceCommand::Connect(connect) = &mut request.command else {
            unreachable!()
        };
        connect.validation_config = config;
        assert_eq!(
            validate_request(&request),
            Err(ServiceErrorCode::InvalidRequest)
        );
    }
}

#[test]
fn rejects_zero_port_or_more_than_64_server_endpoints() {
    let mut zero_port = valid_request();
    let ServiceCommand::Connect(connect) = &mut zero_port.command else {
        unreachable!()
    };
    connect.server_endpoints = vec!["203.0.113.7:0".parse().unwrap()];
    assert_eq!(
        validate_request(&zero_port),
        Err(ServiceErrorCode::InvalidRequest)
    );

    let mut too_many = valid_request();
    let ServiceCommand::Connect(connect) = &mut too_many.command else {
        unreachable!()
    };
    connect.server_endpoints = vec!["203.0.113.7:443".parse().unwrap(); 65];
    assert_eq!(
        validate_request(&too_many),
        Err(ServiceErrorCode::InvalidRequest)
    );
}

#[test]
fn rejects_empty_nul_or_oversized_selector_fields() {
    for (canonical_path, basename) in [
        (String::new(), "game.exe".into()),
        (r"C:\Games\game.exe".into(), "game\0.exe".into()),
        ("x".repeat(4097), "game.exe".into()),
        (r"C:\Games\game.exe".into(), "x".repeat(4097)),
    ] {
        let mut request = valid_request();
        let ServiceCommand::Connect(connect) = &mut request.command else {
            unreachable!()
        };
        connect.excluded_apps = vec![AppSelector {
            canonical_path,
            basename,
        }];
        assert_eq!(
            validate_request(&request),
            Err(ServiceErrorCode::InvalidRequest)
        );
    }
}

#[test]
fn decoding_rejects_invalid_json_and_an_incompatible_response_version() {
    assert_eq!(
        decode_request(b"{not-json"),
        Err(ServiceErrorCode::InvalidFrame)
    );

    let response = ResponseEnvelope {
        version: PROTOCOL_VERSION + 1,
        operation_id: 77,
        result: Ok(ServiceState {
            phase: ConnectionPhase::Disconnected,
            operation_id: 77,
            split_active: false,
            dns_protected: false,
            network_blocked: false,
        }),
    };
    let bytes = serde_json::to_vec(&response).unwrap();
    assert_eq!(
        decode_response(&bytes),
        Err(ServiceErrorCode::UnsupportedVersion)
    );
}

#[test]
fn request_round_trip_preserves_operation_and_connect_fields() {
    let request = valid_request();
    let bytes = encode_payload(&request).unwrap();
    assert_eq!(decode_request(&bytes).unwrap(), request);
}

#[test]
fn intentional_kill_switch_block_is_distinct_from_an_error() {
    let response = ResponseEnvelope {
        version: PROTOCOL_VERSION,
        operation_id: 88,
        result: Ok(ServiceState {
            phase: ConnectionPhase::Blocked,
            operation_id: 88,
            split_active: false,
            dns_protected: false,
            network_blocked: true,
        }),
    };
    let bytes = encode_payload(&response).unwrap();
    assert_eq!(decode_response(&bytes).unwrap(), response);
}
