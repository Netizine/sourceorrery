//! How the provider gets a Vault token.
//!
//! Nothing here reads the manifest: credentials come from where Vault's own
//! tools find them. In order: `VAULT_TOKEN`, the `vault` CLI's
//! `~/.vault-token`, an AppRole (`VAULT_ROLE_ID` and `VAULT_SECRET_ID`), a
//! JWT (`VAULT_AUTH_ROLE` with `VAULT_JWT_FILE` or `VAULT_JWT`) and the
//! Kubernetes service account token (`VAULT_AUTH_ROLE` with the token file
//! a pod carries). `VAULT_AUTH_MOUNT` names the auth method's mount when it
//! is not the default (`approle`, `jwt`, `kubernetes`).

use std::fmt;
use std::path::{Path, PathBuf};

use reqwest::Method;
use sourceorrery_core::{Provider, Result, SecretBytes, SecretError};

use crate::http::Transport;

/// The token file the `vault` CLI writes after `vault login`.
pub const TOKEN_FILE: &str = ".vault-token";
/// Where a Kubernetes pod finds its service account token.
pub const KUBERNETES_TOKEN_FILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

/// A Vault token. Zeroised on drop, redacted in `Debug`, never serialised.
pub struct Token(SecretBytes);

impl Token {
    /// Wrap a token.
    pub fn new(token: impl Into<SecretBytes>) -> Self {
        Self(token.into())
    }

    /// The token, for the request header.
    pub(crate) fn expose(&self) -> &str {
        std::str::from_utf8(self.0.expose()).unwrap_or_default()
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token([REDACTED])")
    }
}

/// How to authenticate. The credential of each variant is a `SecretBytes`
/// and never appears in `Debug` output.
#[derive(Debug)]
pub enum Auth {
    /// A token (`VAULT_TOKEN`, `~/.vault-token`, or given by the caller).
    Token(Token),
    /// `auth/<mount>/login` with an AppRole's role id and secret id.
    AppRole {
        /// The auth method's mount, `approle` by default.
        mount: String,
        /// The role id.
        role_id: String,
        /// The secret id.
        secret_id: SecretBytes,
    },
    /// `auth/<mount>/login` with a JWT (an OIDC or workload identity token).
    Jwt {
        /// The auth method's mount, `jwt` by default.
        mount: String,
        /// The Vault role to log in to.
        role: String,
        /// The token.
        jwt: SecretBytes,
    },
    /// `auth/<mount>/login` with a Kubernetes service account token.
    Kubernetes {
        /// The auth method's mount, `kubernetes` by default.
        mount: String,
        /// The Vault role to log in to.
        role: String,
        /// The service account token.
        jwt: SecretBytes,
    },
}

/// The values the environment gives, so that [`Auth::from_env`] can be
/// tested without touching the process environment.
#[derive(Debug, Default, Clone)]
pub struct Environment {
    /// `VAULT_TOKEN`.
    pub token: Option<String>,
    /// The user's home directory, where `.vault-token` may be.
    pub home: Option<PathBuf>,
    /// `VAULT_ROLE_ID`.
    pub role_id: Option<String>,
    /// `VAULT_SECRET_ID`.
    pub secret_id: Option<String>,
    /// `VAULT_AUTH_ROLE`.
    pub auth_role: Option<String>,
    /// `VAULT_AUTH_MOUNT`.
    pub auth_mount: Option<String>,
    /// `VAULT_JWT_FILE`.
    pub jwt_file: Option<PathBuf>,
    /// `VAULT_JWT`.
    pub jwt: Option<String>,
    /// The Kubernetes service account token file to look for.
    pub kubernetes_token_file: PathBuf,
}

impl Environment {
    /// The process environment.
    pub fn from_process() -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        Self {
            token: var("VAULT_TOKEN"),
            home: std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(PathBuf::from),
            role_id: var("VAULT_ROLE_ID"),
            secret_id: var("VAULT_SECRET_ID"),
            auth_role: var("VAULT_AUTH_ROLE"),
            auth_mount: var("VAULT_AUTH_MOUNT"),
            jwt_file: var("VAULT_JWT_FILE").map(PathBuf::from),
            jwt: var("VAULT_JWT"),
            kubernetes_token_file: PathBuf::from(KUBERNETES_TOKEN_FILE),
        }
    }
}

fn read_credential_file(path: &Path, what: &str) -> Result<Option<SecretBytes>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let trimmed = bytes
                .iter()
                .rposition(|b| !b.is_ascii_whitespace())
                .map_or(0, |i| i + 1);
            let mut bytes = bytes;
            bytes.truncate(trimmed);
            if bytes.is_empty() {
                Ok(None)
            } else {
                Ok(Some(SecretBytes::new(bytes)))
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(SecretError::Io(format!(
            "cannot read {what} {}: {err}",
            path.display()
        ))),
    }
}

/// `auth/<mount>/login`'s reply, the part that matters.
#[derive(serde::Deserialize)]
struct LoginResponse {
    auth: LoginAuth,
}

#[derive(serde::Deserialize)]
struct LoginAuth {
    client_token: String,
}

impl Auth {
    /// The first credential the environment offers, in the documented
    /// order; `unauthenticated` with a hint when there is none.
    pub fn from_env() -> Result<Self> {
        Self::from_environment(&Environment::from_process())
    }

    /// [`Auth::from_env`] over explicit values.
    pub fn from_environment(env: &Environment) -> Result<Self> {
        if let Some(token) = &env.token {
            return Ok(Self::Token(Token::new(token.as_str())));
        }
        if let Some(home) = &env.home
            && let Some(token) = read_credential_file(&home.join(TOKEN_FILE), "the token file")?
        {
            return Ok(Self::Token(Token(token)));
        }
        if let (Some(role_id), Some(secret_id)) = (&env.role_id, &env.secret_id) {
            return Ok(Self::AppRole {
                mount: env
                    .auth_mount
                    .clone()
                    .unwrap_or_else(|| "approle".to_owned()),
                role_id: role_id.clone(),
                secret_id: SecretBytes::from(secret_id.as_str()),
            });
        }
        if let Some(role) = &env.auth_role {
            let jwt = match (&env.jwt_file, &env.jwt) {
                (Some(file), _) => read_credential_file(file, "VAULT_JWT_FILE")?,
                (None, Some(jwt)) => Some(SecretBytes::from(jwt.as_str())),
                (None, None) => None,
            };
            if let Some(jwt) = jwt {
                return Ok(Self::Jwt {
                    mount: env.auth_mount.clone().unwrap_or_else(|| "jwt".to_owned()),
                    role: role.clone(),
                    jwt,
                });
            }
            if let Some(jwt) =
                read_credential_file(&env.kubernetes_token_file, "the service account token")?
            {
                return Ok(Self::Kubernetes {
                    mount: env
                        .auth_mount
                        .clone()
                        .unwrap_or_else(|| "kubernetes".to_owned()),
                    role: role.clone(),
                    jwt,
                });
            }
        }
        Err(SecretError::Unauthenticated {
            provider: Provider::HashicorpVault.name().to_owned(),
            reason: "no VAULT_TOKEN, ~/.vault-token, AppRole (VAULT_ROLE_ID and VAULT_SECRET_ID), \
                     JWT (VAULT_AUTH_ROLE with VAULT_JWT_FILE or VAULT_JWT) or Kubernetes service \
                     account token (VAULT_AUTH_ROLE) was found"
                .to_owned(),
        })
    }

    /// The token this authentication yields: the token itself, or the
    /// client token a login returns.
    pub(crate) async fn login(self, transport: &Transport) -> Result<Token> {
        let (mount, body, what) = match self {
            Self::Token(token) => return Ok(token),
            Self::AppRole {
                mount,
                role_id,
                secret_id,
            } => (
                mount,
                serde_json::json!({
                    "role_id": role_id,
                    "secret_id": String::from_utf8_lossy(secret_id.expose()),
                }),
                "AppRole",
            ),
            Self::Jwt { mount, role, jwt } => (
                mount,
                serde_json::json!({ "role": role, "jwt": String::from_utf8_lossy(jwt.expose()) }),
                "JWT",
            ),
            Self::Kubernetes { mount, role, jwt } => (
                mount,
                serde_json::json!({ "role": role, "jwt": String::from_utf8_lossy(jwt.expose()) }),
                "Kubernetes",
            ),
        };
        let path = format!("auth/{mount}/login");
        let reply = transport
            .expect_ok(Method::POST, &path, None, Some(&body), |status, errors| {
                (status == reqwest::StatusCode::FORBIDDEN
                    || status == reqwest::StatusCode::BAD_REQUEST
                    || status == reqwest::StatusCode::NOT_FOUND)
                    .then(|| SecretError::Unauthenticated {
                        provider: Provider::HashicorpVault.name().to_owned(),
                        reason: format!("{what} login at {path} failed ({status}): {errors}"),
                    })
            })
            .await?;
        let parsed: LoginResponse = reply.json(&path)?;
        Ok(Token::new(parsed.auth.client_token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_environment_is_searched_in_the_documented_order() {
        let dir = tempfile::tempdir().unwrap();
        let none = Environment {
            kubernetes_token_file: dir.path().join("no-sa-token"),
            ..Environment::default()
        };
        let err = Auth::from_environment(&none).unwrap_err();
        assert_eq!(err.code(), "unauthenticated");
        assert!(err.to_string().contains("VAULT_TOKEN"));

        let token = Environment {
            token: Some("hvs.direct".into()),
            role_id: Some("r".into()),
            secret_id: Some("s".into()),
            ..none.clone()
        };
        let auth = Auth::from_environment(&token).unwrap();
        assert!(matches!(&auth, Auth::Token(t) if t.expose() == "hvs.direct"));
        assert!(!format!("{auth:?}").contains("hvs.direct"));

        std::fs::write(dir.path().join(TOKEN_FILE), "hvs.from-file\n").unwrap();
        let file = Environment {
            home: Some(dir.path().to_path_buf()),
            ..none.clone()
        };
        let auth = Auth::from_environment(&file).unwrap();
        assert!(matches!(&auth, Auth::Token(t) if t.expose() == "hvs.from-file"));

        let approle = Environment {
            role_id: Some("r".into()),
            secret_id: Some("SECRET-ID-CANARY".into()),
            auth_mount: Some("approle-prod".into()),
            ..none.clone()
        };
        let auth = Auth::from_environment(&approle).unwrap();
        assert!(
            matches!(&auth, Auth::AppRole { mount, role_id, .. } if mount == "approle-prod" && role_id == "r")
        );
        assert!(
            !format!("{auth:?}").contains("SECRET-ID-CANARY"),
            "{auth:?}"
        );

        let jwt_path = dir.path().join("jwt");
        std::fs::write(&jwt_path, "eyJ.header.sig\n").unwrap();
        let jwt = Environment {
            auth_role: Some("ci".into()),
            jwt_file: Some(jwt_path),
            ..none.clone()
        };
        assert!(matches!(
            Auth::from_environment(&jwt).unwrap(),
            Auth::Jwt { mount, role, .. } if mount == "jwt" && role == "ci"
        ));

        let sa_path = dir.path().join("sa-token");
        std::fs::write(&sa_path, "eyJ.sa.sig").unwrap();
        let k8s = Environment {
            auth_role: Some("app".into()),
            kubernetes_token_file: sa_path,
            ..none.clone()
        };
        assert!(matches!(
            Auth::from_environment(&k8s).unwrap(),
            Auth::Kubernetes { mount, role, .. } if mount == "kubernetes" && role == "app"
        ));

        // A role without any token is still unauthenticated.
        let role_only = Environment {
            auth_role: Some("app".into()),
            ..none
        };
        assert_eq!(
            Auth::from_environment(&role_only).unwrap_err().code(),
            "unauthenticated"
        );
    }
}
