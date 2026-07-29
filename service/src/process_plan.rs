use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrayInvocationKind {
    Validate,
    Run,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrayInvocation {
    pub kind: XrayInvocationKind,
    pub executable: PathBuf,
    pub arguments: Vec<String>,
}

impl XrayInvocation {
    pub fn validation(executable: PathBuf, config: PathBuf) -> Self {
        Self {
            kind: XrayInvocationKind::Validate,
            executable,
            arguments: vec![
                "run".into(),
                "-test".into(),
                "-c".into(),
                config.to_string_lossy().into_owned(),
            ],
        }
    }

    pub fn run(executable: PathBuf, config: PathBuf) -> Self {
        Self {
            kind: XrayInvocationKind::Run,
            executable,
            arguments: vec![
                "run".into(),
                "-c".into(),
                config.to_string_lossy().into_owned(),
            ],
        }
    }
}
