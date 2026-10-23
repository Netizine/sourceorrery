pub mod audit;
pub mod audit_export;
pub mod backup;
pub mod completions;
pub mod import;
pub mod project;
pub mod rotate;
pub mod secret;
pub mod vault;

use std::collections::BTreeMap;

use anyhow::anyhow;

/// Parse repeated `key=value` tag arguments.
pub fn parse_tags(raw: &[String]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut tags = BTreeMap::new();
    for item in raw {
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| anyhow!("tag '{item}' must be key=value"))?;
        if key.trim().is_empty() {
            return Err(anyhow!("tag '{item}' has an empty key"));
        }
        tags.insert(key.trim().to_owned(), value.to_owned());
    }
    Ok(tags)
}
