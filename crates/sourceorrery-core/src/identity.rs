//! Principals: who is asking.
//!
//! Milestone 1 only knows the local OS user. The type exists now so that
//! audit records and policy hooks carry a principal from day one, and so the
//! broker can introduce verified workload and agent identities without
//! changing the contract.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Category of principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// An interactive human user (the OS account for local vaults).
    User,
    /// An application or service with its own verified identity.
    Workload,
    /// An AI coding agent session. Starts with no production privileges.
    Agent,
    /// SourceOrrery itself (maintenance, scheduled purge, ...).
    System,
}

impl PrincipalKind {
    /// Stable lowercase label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Workload => "workload",
            Self::Agent => "agent",
            Self::System => "system",
        }
    }
}

/// An identity that performs operations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Principal {
    /// What kind of thing this is.
    pub kind: PrincipalKind,
    /// Stable identifier within its kind (OS user name, workload id, ...).
    pub id: String,
}

impl Principal {
    /// Build a principal.
    pub fn new(kind: PrincipalKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }

    /// The current operating-system user, best effort.
    ///
    /// This is a *label* for audit purposes, not a verified identity. A
    /// process running as the same OS user can claim the same name.
    pub fn local_user() -> Self {
        let name = ["SOURCEORRERY_ACTOR", "USER", "USERNAME", "LOGNAME"]
            .iter()
            .find_map(|key| std::env::var(key).ok().filter(|v| !v.trim().is_empty()))
            .unwrap_or_else(|| "unknown".to_owned());
        Self::new(PrincipalKind::User, name)
    }

    /// SourceOrrery acting on its own behalf.
    pub fn system() -> Self {
        Self::new(PrincipalKind::System, "sourceorrery")
    }

    /// Parse the `kind:id` form produced by `Display`.
    pub fn parse(label: &str) -> Option<Self> {
        let (kind, id) = label.split_once(':')?;
        let kind = match kind {
            "user" => PrincipalKind::User,
            "workload" => PrincipalKind::Workload,
            "agent" => PrincipalKind::Agent,
            "system" => PrincipalKind::System,
            _ => return None,
        };
        Some(Self::new(kind, id))
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind.as_str(), self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_round_trips() {
        let p = Principal::new(PrincipalKind::Agent, "claude-session-1");
        assert_eq!(p.to_string(), "agent:claude-session-1");
        assert_eq!(Principal::parse(&p.to_string()), Some(p));
        assert_eq!(Principal::parse("nonsense"), None);
    }

    #[test]
    fn local_user_is_never_empty() {
        assert_ne!(Principal::local_user().id, "");
    }
}
