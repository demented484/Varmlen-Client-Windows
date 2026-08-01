const HOOKS: &str = include_str!("../../src-tauri/windows/installer-hooks.nsh");

fn macro_body(name: &str) -> &str {
    let start = HOOKS
        .find(&format!("!macro {name}"))
        .expect("installer macro exists");
    let rest = &HOOKS[start..];
    let end = rest.find("!macroend").expect("installer macro ends");
    &rest[..end]
}

#[test]
fn upgrade_does_not_delete_the_service_before_new_files_are_ready() {
    let preinstall = macro_body("NSIS_HOOK_PREINSTALL");
    assert!(!preinstall.contains("sc.exe delete VarmlenService"));
    assert!(preinstall.contains("varmlen-service.exe"));
    assert!(HOOKS.contains("VARMLEN_ROLLBACK_SERVICE"));
}

#[test]
fn install_waits_for_ipc_readiness_and_does_not_grant_user_modify() {
    let postinstall = macro_body("NSIS_HOOK_POSTINSTALL");
    assert!(postinstall.contains("--health"));
    assert!(postinstall.contains("sc.exe config VarmlenService"));
    assert!(!HOOKS.contains("(OI)(CI)M"));
}

#[test]
fn uninstall_aborts_before_deleting_recovery_when_cleanup_fails() {
    let uninstall = macro_body("NSIS_HOOK_PREUNINSTALL");
    assert!(uninstall.contains("ExecToStack"));
    assert!(uninstall.contains("--cleanup"));
    assert!(uninstall.contains("Abort"));
}
