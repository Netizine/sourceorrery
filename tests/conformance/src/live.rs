//! For the providers' live tests: what they run against, and a refusal to
//! pass without running when a CI job says they must.
//!
//! A live test runs when its endpoint variable names a server, and is
//! skipped otherwise, so `cargo test` passes on a machine without one. In
//! a job that starts the server, `SOURCEORRERY_LIVE_REQUIRED=true` turns a
//! missing endpoint into a failure: the suite cannot pass there without
//! having run.

/// Set to `true` where a live suite must run.
pub const REQUIRED_ENV: &str = "SOURCEORRERY_LIVE_REQUIRED";

/// The endpoint `env` names, or `None` to skip the test. Says on stderr
/// what the test runs against: an emulator or dev server on this machine,
/// or a service elsewhere.
///
/// # Panics
///
/// When `env` is unset and [`REQUIRED_ENV`] is `true`.
pub fn target(env: &str) -> Option<String> {
    let found = std::env::var(env)
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_end_matches('/').to_owned());
    match &found {
        Some(url) => eprintln!(
            "live: against {url} ({})",
            if is_local(url) {
                "an emulator or dev server on this machine"
            } else {
                "a service"
            }
        ),
        None => assert!(
            std::env::var(REQUIRED_ENV).as_deref() != Ok("true"),
            "{REQUIRED_ENV} is true but {env} is not set: the live tests would pass without \
             running"
        ),
    }
    found
}

/// True for a loopback address or LocalStack's local names.
fn is_local(url: &str) -> bool {
    let host = url
        .split_once("://")
        .map_or(url, |(_, rest)| rest)
        .split(['/', '?'])
        .next()
        .unwrap_or_default();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.split_once(']'))
        .map_or_else(|| host.split(':').next().unwrap_or_default(), |(h, _)| h);
    host == "localhost"
        || host.ends_with(".localhost")
        || host.starts_with("127.")
        || host == "::1"
        || host == "localhost.localstack.cloud"
        || host.ends_with(".localhost.localstack.cloud")
}

#[cfg(test)]
mod tests {
    use super::is_local;

    #[test]
    fn local_targets_are_told_from_services() {
        for local in [
            "http://127.0.0.1:8200",
            "http://localhost:4566",
            "http://[::1]:8200/",
            "https://azure.localhost.localstack.cloud:4567",
        ] {
            assert!(is_local(local), "{local}");
        }
        for service in [
            "https://vault.example.com:8200",
            "https://secretsmanager.eu-west-1.amazonaws.com",
            "https://localhost.example.com",
        ] {
            assert!(!is_local(service), "{service}");
        }
    }
}
