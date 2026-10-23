//! The HTTP transport: one Vault API call, with its status mapped to a
//! `SecretError` and its body kept out of every message.

use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use sourceorrery_core::{Provider, Result, SecretError};
use zeroize::Zeroizing;

use crate::auth::Token;

/// Vault's `{"errors": [...]}` body.
#[derive(serde::Deserialize, Default)]
struct ErrorBody {
    #[serde(default)]
    errors: Vec<String>,
}

/// What a call returned: the status and the raw body, zeroised on drop
/// because a body may carry a value.
pub(crate) struct Reply {
    pub status: StatusCode,
    pub body: Zeroizing<Vec<u8>>,
}

impl Reply {
    /// Parse the body as `T`; a body that does not fit is a `storage` error
    /// that names the path, never the body.
    pub fn json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|err| {
            SecretError::Storage(format!(
                "{} returned an unexpected body for {path}: {} at line {}, column {}",
                Provider::HashicorpVault.display_name(),
                err.classify_text(),
                err.line(),
                err.column()
            ))
        })
    }

    /// The `errors` strings Vault put in a failure body, joined, truncated.
    /// They are Vault's own diagnostics (`permission denied`, a missing
    /// field name) and never hold a secret value.
    fn vault_errors(&self) -> String {
        let parsed: ErrorBody = serde_json::from_slice(&self.body).unwrap_or_default();
        let mut text = parsed.errors.join("; ");
        if text.len() > 200 {
            let mut end = 200;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push('…');
        }
        text
    }
}

/// A category-only description of a JSON parse error.
trait Classify {
    fn classify_text(&self) -> &'static str;
}

impl Classify for serde_json::Error {
    fn classify_text(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io => "an I/O error",
            serde_json::error::Category::Syntax => "invalid JSON",
            serde_json::error::Category::Data => "a different shape than expected",
            serde_json::error::Category::Eof => "a truncated body",
        }
    }
}

/// The server behind a client: address, namespace, TLS settings.
#[derive(Clone, Debug)]
pub(crate) struct Transport {
    http: reqwest::Client,
    base: String,
    namespace: Option<String>,
}

impl Transport {
    /// A transport for `address` (`https://host:8200`, no trailing slash
    /// needed). `ca_pem` adds a root certificate for a private CA.
    pub fn new(address: &str, namespace: Option<String>, ca_pem: Option<&[u8]>) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(60))
            .user_agent(concat!("sourceorrery/", env!("CARGO_PKG_VERSION")))
            .https_only(address.starts_with("https://"));
        if let Some(pem) = ca_pem {
            let cert = reqwest::Certificate::from_pem(pem).map_err(|err| {
                SecretError::InvalidArgument(format!(
                    "VAULT_CACERT is not a PEM certificate: {err}"
                ))
            })?;
            builder = builder.add_root_certificate(cert);
        }
        let http = builder
            .build()
            .map_err(|err| SecretError::Io(format!("cannot build the HTTP client: {err}")))?;
        Ok(Self {
            http,
            base: address.trim_end_matches('/').to_owned(),
            namespace,
        })
    }

    /// The server address, for descriptors and messages.
    pub fn address(&self) -> &str {
        &self.base
    }

    /// One call to `/v1/<path>`. `body` is sent as JSON. A network failure
    /// or a 5xx is `provider_unavailable`; every other status is returned
    /// for the caller to interpret, with the body.
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&Token>,
        body: Option<&serde_json::Value>,
    ) -> Result<Reply> {
        let url = format!("{}/v1/{path}", self.base);
        let mut request = self
            .http
            .request(method, &url)
            .header("X-Vault-Request", "true");
        if let Some(namespace) = &self.namespace {
            request = request.header("X-Vault-Namespace", namespace);
        }
        if let Some(token) = token {
            request = request.header("X-Vault-Token", token.expose());
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        tracing::debug!(path, "vault request");
        let response = request.send().await.map_err(unavailable)?;
        let status = response.status();
        let body = Zeroizing::new(response.bytes().await.map_err(unavailable)?.to_vec());
        let reply = Reply { status, body };
        if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
            return Err(SecretError::ProviderUnavailable {
                provider: Provider::HashicorpVault.name().to_owned(),
                reason: format!("{path} answered {status}: {}", reply.vault_errors()),
            });
        }
        Ok(reply)
    }

    /// `call`, treating anything but a 2xx as the error `on_status` maps it
    /// to, with 403 as `permission_denied` and 400 as `invalid_argument` by
    /// default.
    pub async fn expect_ok(
        &self,
        method: Method,
        path: &str,
        token: Option<&Token>,
        body: Option<&serde_json::Value>,
        on_status: impl Fn(StatusCode, String) -> Option<SecretError>,
    ) -> Result<Reply> {
        let reply = self.call(method, path, token, body).await?;
        if reply.status.is_success() {
            return Ok(reply);
        }
        let errors = reply.vault_errors();
        if let Some(err) = on_status(reply.status, errors.clone()) {
            return Err(err);
        }
        Err(default_error(path, reply.status, &errors))
    }
}

/// The error for a request that could not be sent or answered.
fn unavailable(err: reqwest::Error) -> SecretError {
    // `reqwest::Error`'s Display includes the URL, which holds the address
    // and a secret's name, never a value; it never includes a body.
    let reason = if err.is_timeout() {
        "the request timed out".to_owned()
    } else if err.is_connect() {
        format!("cannot connect: {}", err.without_url())
    } else {
        err.without_url().to_string()
    };
    SecretError::ProviderUnavailable {
        provider: Provider::HashicorpVault.name().to_owned(),
        reason,
    }
}

/// The error for a non-2xx status no caller-specific rule claimed.
pub(crate) fn default_error(path: &str, status: StatusCode, errors: &str) -> SecretError {
    match status {
        StatusCode::FORBIDDEN => SecretError::PermissionDenied(format!(
            "{} refused {path}: {}",
            Provider::HashicorpVault.display_name(),
            if errors.is_empty() {
                "permission denied"
            } else {
                errors
            }
        )),
        StatusCode::BAD_REQUEST => SecretError::InvalidArgument(format!(
            "{} rejected {path}: {errors}",
            Provider::HashicorpVault.display_name()
        )),
        _ => SecretError::Storage(format!(
            "{} answered {status} for {path}: {errors}",
            Provider::HashicorpVault.display_name()
        )),
    }
}
