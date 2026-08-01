use varmlen_service::pipe_policy::{
    pipe_security_descriptor_sddl, InstalledUserSid, PipeClientIdentity, CLIENT_IO_TIMEOUT,
    MAX_CONCURRENT_CLIENTS,
};
use varmlen_service::{PIPE_NAME, SERVICE_NAME};

#[test]
fn service_and_pipe_names_are_stable() {
    assert_eq!(SERVICE_NAME, "VarmlenService");
    assert_eq!(PIPE_NAME, r"\\.\pipe\Varmlen\Service\v1");
}

#[test]
fn denies_remote_or_wrong_sid_pipe_clients() {
    let installed = InstalledUserSid::parse("S-1-5-21-100-200-300-1001").unwrap();
    let wrong = InstalledUserSid::parse("S-1-5-21-100-200-300-1002").unwrap();

    assert!(!PipeClientIdentity::remote(installed.clone()).authorize(&installed));
    assert!(!PipeClientIdentity::local(wrong).authorize(&installed));
    assert!(PipeClientIdentity::local(installed.clone()).authorize(&installed));
    assert!(PipeClientIdentity::local_system().authorize(&installed));
}

#[test]
fn rejects_malformed_installed_user_sids() {
    for value in [
        "",
        "S-1",
        "S-1-five-21",
        "S-1-5-21-",
        " S-1-5-21-1001",
        "S-1-5-21-1001\0",
    ] {
        assert!(InstalledUserSid::parse(value).is_err(), "{value:?}");
    }
}

#[test]
fn pipe_acl_grants_only_system_admins_and_the_installed_user() {
    let installed = InstalledUserSid::parse("S-1-5-21-100-200-300-1001").unwrap();

    assert_eq!(
        pipe_security_descriptor_sddl(&installed),
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-100-200-300-1001)"
    );
}

#[test]
fn pipe_clients_are_bounded_and_have_an_io_deadline() {
    assert!((1..=32).contains(&MAX_CONCURRENT_CLIENTS));
    assert!(CLIENT_IO_TIMEOUT >= std::time::Duration::from_secs(1));
    assert!(CLIENT_IO_TIMEOUT <= std::time::Duration::from_secs(10));
}
