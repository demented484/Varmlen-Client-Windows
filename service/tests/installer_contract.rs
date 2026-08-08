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
    assert!(postinstall.contains("sc.exe sdset VarmlenService"));
    assert!(postinstall.contains(";;;SY"));
    assert!(postinstall.contains(";;;BA"));
    assert!(postinstall.contains(";;;IU"));
    assert!(postinstall.contains("$COMMONPROGRAMDATA\\Varmlen"));
    assert!(postinstall.contains("SetSecurityDescriptorSddlForm"));
    assert!(postinstall.contains("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"));
    assert!(!HOOKS.contains("$COMMONAPPDATA"));
    assert!(!HOOKS.contains("(OI)(CI)M"));
}

#[test]
fn uninstall_is_never_held_hostage_by_legacy_wfp_cleanup() {
    let uninstall = macro_body("NSIS_HOOK_PREUNINSTALL");
    assert!(uninstall.contains("ExecToStack"));
    assert!(uninstall.contains("--cleanup"));
    let cleanup_warning = uninstall
        .find("Legacy WFP cleanup warning")
        .expect("cleanup warning exists");
    let service_query = uninstall
        .find("sc.exe query VarmlenService")
        .expect("service existence is checked");
    let service_delete = uninstall
        .find("sc.exe delete VarmlenService")
        .expect("registered service is deleted");
    assert!(cleanup_warning < service_query);
    assert!(service_query < service_delete);
    assert!(!uninstall[cleanup_warning..service_query].contains("Abort"));
    assert!(uninstall.contains("already absent; continuing uninstallation"));
}

#[test]
fn powershell_hooks_preserve_single_quoted_powershell_literals() {
    let powershell_hooks = HOOKS
        .lines()
        .filter(|line| line.contains("powershell.exe"))
        .collect::<Vec<_>>();

    assert_eq!(powershell_hooks.len(), 4);
    for hook in powershell_hooks {
        assert!(hook.contains(" `powershell.exe"));
        assert!(hook.ends_with('`'));
        assert!(!hook.contains("''"));
    }
}

#[test]
fn powershell_hooks_fit_nsis_string_limit() {
    const NSIS_MAX_STRLEN: usize = 1024;

    for hook in HOOKS.lines().filter(|line| line.contains("powershell.exe")) {
        let expanded = hook
            .replace("$$", "$")
            .replace("$COMMONPROGRAMDATA", r"C:\ProgramData")
            .replace("$INSTDIR", r"C:\Program Files\Varmlen");

        assert!(
            expanded.chars().count() < NSIS_MAX_STRLEN,
            "PowerShell hook exceeds NSIS_MAX_STRLEN: {} characters",
            expanded.chars().count()
        );
    }
}

#[cfg(windows)]
#[test]
fn embedded_powershell_scripts_parse_on_windows() {
    const PARSE_COMMAND: &str = "$tokens = $null; $errors = $null; \
        [void][System.Management.Automation.Language.Parser]::ParseInput(\
            $env:VARMLEN_INSTALLER_SCRIPT, [ref]$tokens, [ref]$errors); \
        if ($errors.Count -ne 0) { \
            $errors | ForEach-Object { [Console]::Error.WriteLine($_.Message) }; \
            exit 1 \
        }";

    for hook in HOOKS.lines().filter(|line| line.contains("powershell.exe")) {
        let command_start = hook.find("-Command \"").expect("PowerShell command starts") + 10;
        let command_end = hook.rfind("\"`").expect("PowerShell command ends");
        let script = hook[command_start..command_end]
            .replace("$COMMONPROGRAMDATA", r"C:\ProgramData")
            .replace("$INSTDIR", r"C:\Program Files\Varmlen")
            .replace("$$", "$");

        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                PARSE_COMMAND,
            ])
            .env("VARMLEN_INSTALLER_SCRIPT", script)
            .output()
            .expect("PowerShell parser starts");

        assert!(
            output.status.success(),
            "embedded PowerShell failed parsing: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
