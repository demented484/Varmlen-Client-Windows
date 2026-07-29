#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstalledUserSid(String);

impl InstalledUserSid {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        if value.is_empty()
            || value.len() > 184
            || value.trim() != value
            || value.as_bytes().contains(&0)
        {
            return Err("invalid SID text");
        }

        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() < 4 || parts.len() > 18 || parts[0] != "S" || parts[1] != "1" {
            return Err("invalid SID structure");
        }
        let authority = parts[2]
            .parse::<u64>()
            .map_err(|_| "invalid SID authority")?;
        let subauthorities = parts[3..]
            .iter()
            .map(|part| {
                if part.is_empty() {
                    Err("empty SID subauthority")
                } else {
                    part.parse::<u32>().map_err(|_| "invalid SID subauthority")
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut canonical = format!("S-1-{authority}");
        for subauthority in subauthorities {
            canonical.push('-');
            canonical.push_str(&subauthority.to_string());
        }
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClientOrigin {
    Local(InstalledUserSid),
    LocalSystem,
    Remote,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeClientIdentity {
    origin: ClientOrigin,
}

impl PipeClientIdentity {
    pub fn local(sid: InstalledUserSid) -> Self {
        Self {
            origin: ClientOrigin::Local(sid),
        }
    }

    pub fn local_system() -> Self {
        Self {
            origin: ClientOrigin::LocalSystem,
        }
    }

    pub fn remote(_sid: InstalledUserSid) -> Self {
        Self {
            origin: ClientOrigin::Remote,
        }
    }

    pub fn authorize(&self, installed_user: &InstalledUserSid) -> bool {
        match &self.origin {
            ClientOrigin::Local(sid) => sid == installed_user,
            ClientOrigin::LocalSystem => true,
            ClientOrigin::Remote => false,
        }
    }
}

pub fn pipe_security_descriptor_sddl(installed_user: &InstalledUserSid) -> String {
    format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{})",
        installed_user.as_str()
    )
}
