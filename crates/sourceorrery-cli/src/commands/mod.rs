pub mod audit;
pub mod audit_export;
pub mod backup;
pub mod completions;
pub mod guard;
pub mod import;
pub mod project;
pub mod rotate;
pub mod secret;
pub mod setup;
pub mod vault;

use std::collections::BTreeMap;

use anyhow::anyhow;

/// Prefix of the tags SourceOrrery writes for itself (rotation state, the
/// origin of a restored version); not for a `--tag` argument.
pub const RESERVED_TAG_PREFIX: &str = "sourceorrery.";

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
        if key.trim().starts_with(RESERVED_TAG_PREFIX) {
            // Rotation and restore record their state in these; a hand-set
            // one would be taken for theirs.
            return Err(anyhow!(
                "tag keys starting with '{RESERVED_TAG_PREFIX}' are SourceOrrery's own; choose \
                 another key"
            ));
        }
        tags.insert(key.trim().to_owned(), value.to_owned());
    }
    Ok(tags)
}
