//! Changes made in the browser: the forms that collect them and the
//! confirmations that say what will happen. Nothing here touches the
//! vault; the app carries out a confirmed [`Change`] through
//! [`super::editor::MetadataEditor`].
//!
//! Every change is checked here first, with core's own rules and what the
//! secret's storage can express ([`Capability`]), so a change the vault or
//! its provider would refuse (and record as a failure) is never sent.

use sourceorrery_core::{
    Capability, SecretError, SecretProperties, SetSecretOptions, UpdateSecretProperties, timestamp,
    validate_secret_name,
};
use sourceorrery_storage::{ProjectLink, SecretStorage};
use time::{Duration, OffsetDateTime};

use crate::commands::parse_tags;
use crate::output;

/// What is open over the views.
#[derive(Debug)]
pub enum Dialog {
    Form(Form),
    Confirm(Confirm),
}

/// A change, ready to carry out.
#[derive(Clone, Debug)]
pub enum Change {
    Update {
        name: String,
        version: String,
        update: UpdateSecretProperties,
    },
    Delete {
        name: String,
    },
    Recover {
        name: String,
    },
    /// Needs its value from the hidden prompt first. `storage` is where a
    /// new secret is created; a version of an existing one goes where it
    /// is kept.
    AddVersion {
        name: String,
        options: SetSecretOptions,
        storage: Option<SecretStorage>,
    },
    /// Forget a project folder that is gone.
    Unlink {
        id: String,
        name: String,
    },
}

/// Where a secret is kept, as a form checks a change against it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept {
    /// The storage, as a person reads it: `the vault`, `HashiCorp Vault`.
    pub place: String,
    pub capabilities: &'static [Capability],
}

impl Default for Kept {
    /// The vault file, which can express everything.
    fn default() -> Self {
        Self {
            place: "the vault".to_owned(),
            capabilities: Capability::ALL,
        }
    }
}

impl Kept {
    fn can(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// A storage a new secret can be created in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageChoice {
    pub label: String,
    pub storage: SecretStorage,
    pub kept: Kept,
}

/// The last step before a change: what it does, and Enter to do it.
#[derive(Debug)]
pub struct Confirm {
    pub title: String,
    pub lines: Vec<String>,
    pub change: Change,
    /// A change that cannot be undone: this must be typed first.
    pub must_type: Option<String>,
    pub typed: String,
    pub error: Option<String>,
}

impl Confirm {
    fn new(title: &str, lines: Vec<String>, change: Change) -> Self {
        Self {
            title: title.to_owned(),
            lines,
            change,
            must_type: None,
            typed: String::new(),
            error: None,
        }
    }

    /// Enable a disabled version, or disable an enabled one.
    pub fn toggle(p: &SecretProperties) -> Self {
        let enable = !p.enabled;
        let what = format!("Version {} of '{}'", p.version, output::sanitize(&p.name));
        let (title, effect) = if enable {
            (
                "ENABLE VERSION",
                "can be read again, within its time window.",
            )
        } else {
            (
                "DISABLE VERSION",
                "can no longer be read, by anyone, until it is enabled again.",
            )
        };
        Self::new(
            title,
            vec![what, format!("It {effect}")],
            Change::Update {
                name: p.name.clone(),
                version: p.version.clone(),
                update: UpdateSecretProperties {
                    enabled: Some(enable),
                    ..UpdateSecretProperties::default()
                },
            },
        )
    }

    /// Delete a secret: soft in a recoverable vault, for good in a
    /// purgeable one (which must then be typed to confirm).
    pub fn delete(name: &str, purgeable: bool, retention_days: u32, now: OffsetDateTime) -> Self {
        let shown = output::sanitize(name).into_owned();
        let change = Change::Delete {
            name: name.to_owned(),
        };
        if purgeable {
            let mut confirm = Self::new(
                "DELETE FOR GOOD",
                vec![
                    format!(
                        "The vault is purgeable: '{shown}' and every version are deleted at once."
                    ),
                    "This cannot be undone.".to_owned(),
                ],
                change,
            );
            confirm.must_type = Some(name.to_owned());
            return confirm;
        }
        let until = output::fmt_time(now + Duration::days(i64::from(retention_days)));
        Self::new(
            "DELETE",
            vec![
                format!("'{shown}' and every version are soft-deleted."),
                format!(
                    "They stay recoverable for {retention_days} days, until {until}: u on the \
                     Deleted view, or `sourceorrery secret recover {shown}`."
                ),
            ],
            change,
        )
    }

    pub fn recover(name: &str) -> Self {
        let shown = output::sanitize(name);
        Self::new(
            "RECOVER",
            vec![format!(
                "'{shown}' and every version come back from the deleted secrets."
            )],
            Change::Recover {
                name: name.to_owned(),
            },
        )
    }

    /// Forget a project folder that is gone: the vault's record of it, not
    /// a file.
    pub fn unlink(link: &ProjectLink) -> Self {
        let path = output::sanitize(&link.path.display().to_string()).into_owned();
        Self::new(
            "FORGET PROJECT",
            vec![
                format!(
                    "The vault forgets project '{}' at {path}.",
                    output::sanitize(&link.name)
                ),
                "Its folder or manifest is gone; nothing on disk is touched. Running `init` \
                 there again records it again."
                    .to_owned(),
            ],
            Change::Unlink {
                id: link.id.clone(),
                name: link.name.clone(),
            },
        )
    }

    pub fn input(&mut self, c: char) {
        if self.must_type.is_some() {
            self.typed.push(c);
            self.error = None;
        }
    }

    pub fn erase(&mut self) {
        self.typed.pop();
    }

    /// Whatever must be typed has been.
    pub fn ready(&self) -> Result<(), String> {
        match &self.must_type {
            Some(name) if self.typed != *name => {
                Err(format!("type '{}' to confirm", output::sanitize(name)))
            }
            _ => Ok(()),
        }
    }
}

/// The fields a form can have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKey {
    Name,
    Storage,
    Enabled,
    ContentType,
    Tags,
    NotBefore,
    Expires,
}

impl FieldKey {
    pub fn label(self) -> &'static str {
        match self {
            FieldKey::Name => "name",
            FieldKey::Storage => "kept in",
            FieldKey::Enabled => "enabled",
            FieldKey::ContentType => "content type",
            FieldKey::Tags => "tags",
            FieldKey::NotBefore => "not before",
            FieldKey::Expires => "expires",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            FieldKey::Name => "letters, digits and hyphens",
            FieldKey::Storage => "space for the next of the vault's storages",
            FieldKey::Enabled => "space switches yes and no",
            FieldKey::ContentType => "e.g. text/plain; empty for none",
            FieldKey::Tags => "key=value, comma-separated; not secret",
            FieldKey::NotBefore | FieldKey::Expires => {
                "RFC 3339, e.g. 2026-12-01T00:00:00Z; empty for none"
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Field {
    pub key: FieldKey,
    pub value: String,
    /// The value the form started with: unchanged fields change nothing.
    original: String,
}

/// What a form is for.
#[derive(Clone, Debug)]
pub enum Purpose {
    /// Change this version's metadata.
    Edit { current: SecretProperties },
    /// A new version of an existing secret.
    NewVersion { name: String },
    /// A new secret, or a new version if a live secret has the name.
    Add {
        live: Vec<String>,
        deleted: Vec<String>,
    },
}

#[derive(Debug)]
pub struct Form {
    pub title: String,
    pub purpose: Purpose,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub error: Option<String>,
    /// Where the secret is kept: an edit or a new version is checked
    /// against it.
    pub kept: Kept,
    /// The version edited is the secret's newest.
    newest: bool,
    /// The storages a new secret can be created in, and the one chosen.
    storages: Vec<StorageChoice>,
    storage: usize,
}

fn field(key: FieldKey, value: String) -> Field {
    Field {
        key,
        original: value.clone(),
        value,
    }
}

fn yes_no(on: bool) -> String {
    if on { "yes" } else { "no" }.to_owned()
}

fn tags_text(p: &SecretProperties) -> String {
    p.tags
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn time_text(t: Option<OffsetDateTime>) -> String {
    t.map(output::fmt_time).unwrap_or_default()
}

impl Form {
    /// Change one version's metadata, starting from what it has.
    pub fn edit(current: &SecretProperties) -> Self {
        Self {
            title: format!(
                "CHANGE VERSION {} OF '{}'",
                current.version.chars().take(8).collect::<String>(),
                output::sanitize(&current.name)
            ),
            fields: vec![
                field(FieldKey::Enabled, yes_no(current.enabled)),
                field(
                    FieldKey::ContentType,
                    current.content_type.clone().unwrap_or_default(),
                ),
                field(FieldKey::Tags, tags_text(current)),
                field(FieldKey::NotBefore, time_text(current.not_before)),
                field(FieldKey::Expires, time_text(current.expires_on)),
            ],
            purpose: Purpose::Edit {
                current: current.clone(),
            },
            focus: 0,
            error: None,
            kept: Kept::default(),
            newest: true,
            storages: Vec::new(),
            storage: 0,
        }
    }

    /// A new version, with the newest version's content type and tags.
    pub fn new_version(newest: &SecretProperties) -> Self {
        Self {
            title: format!("NEW VERSION OF '{}'", output::sanitize(&newest.name)),
            fields: vec![
                field(FieldKey::Enabled, yes_no(true)),
                field(
                    FieldKey::ContentType,
                    newest.content_type.clone().unwrap_or_default(),
                ),
                field(FieldKey::Tags, tags_text(newest)),
                field(FieldKey::NotBefore, String::new()),
                field(FieldKey::Expires, String::new()),
            ],
            purpose: Purpose::NewVersion {
                name: newest.name.clone(),
            },
            focus: 0,
            error: None,
            kept: Kept::default(),
            newest: true,
            storages: Vec::new(),
            storage: 0,
        }
    }

    /// A new secret. `live` and `deleted` are the names the vault has.
    pub fn add(live: Vec<String>, deleted: Vec<String>) -> Self {
        Self {
            title: "NEW SECRET".to_owned(),
            fields: vec![
                field(FieldKey::Name, String::new()),
                field(FieldKey::Enabled, yes_no(true)),
                field(FieldKey::ContentType, String::new()),
                field(FieldKey::Tags, String::new()),
                field(FieldKey::NotBefore, String::new()),
                field(FieldKey::Expires, String::new()),
            ],
            purpose: Purpose::Add { live, deleted },
            focus: 0,
            error: None,
            kept: Kept::default(),
            newest: true,
            storages: Vec::new(),
            storage: 0,
        }
    }

    /// The secret is kept in `kept`, and the version is (or is not) its
    /// newest.
    #[must_use]
    pub fn kept_in(mut self, kept: Kept, newest: bool) -> Self {
        self.kept = kept;
        self.newest = newest;
        self
    }

    /// A new secret can go to any of `storages` (the first is the default);
    /// with more than one, the form asks which.
    #[must_use]
    pub fn storing_in(mut self, storages: Vec<StorageChoice>) -> Self {
        if let Some(first) = storages.first() {
            self.kept = first.kept.clone();
            if storages.len() > 1 {
                self.fields
                    .insert(1, field(FieldKey::Storage, first.label.clone()));
            }
        }
        self.storages = storages;
        self.storage = 0;
        self
    }

    pub fn next(&mut self) {
        self.focus = (self.focus + 1) % self.fields.len();
    }

    pub fn prev(&mut self) {
        self.focus = (self.focus + self.fields.len() - 1) % self.fields.len();
    }

    pub fn input(&mut self, c: char) {
        self.error = None;
        if self.fields[self.focus].key == FieldKey::Storage {
            if c == ' ' && !self.storages.is_empty() {
                self.storage = (self.storage + 1) % self.storages.len();
                let choice = &self.storages[self.storage];
                self.kept = choice.kept.clone();
                choice.label.clone_into(&mut self.fields[self.focus].value);
            }
            return;
        }
        let field = &mut self.fields[self.focus];
        if field.key == FieldKey::Enabled {
            if c == ' ' || c == 'y' || c == 'n' {
                let on = match c {
                    'y' => true,
                    'n' => false,
                    _ => field.value != "yes",
                };
                field.value = yes_no(on);
            }
            return;
        }
        if !c.is_control() {
            field.value.push(c);
        }
    }

    pub fn erase(&mut self) {
        let field = &mut self.fields[self.focus];
        if !matches!(field.key, FieldKey::Enabled | FieldKey::Storage) {
            field.value.pop();
        }
    }

    /// The storage chosen for a new secret.
    pub fn chosen_storage(&self) -> Option<&StorageChoice> {
        self.storages.get(self.storage)
    }

    fn value(&self, key: FieldKey) -> Option<&Field> {
        self.fields.iter().find(|f| f.key == key)
    }

    /// Check the form and say what it would do.
    pub fn submit(&self, now: OffsetDateTime) -> Result<Confirm, String> {
        match &self.purpose {
            Purpose::Edit { current } => self.submit_edit(current, now),
            Purpose::NewVersion { name } => {
                let options = self.options()?;
                Ok(new_version_confirm(name, None, &options))
            }
            Purpose::Add { live, deleted } => {
                let name = self
                    .value(FieldKey::Name)
                    .map(|f| f.value.trim().to_owned())
                    .unwrap_or_default();
                validate_secret_name(&name).map_err(reason)?;
                if deleted.contains(&name) {
                    return Err(format!(
                        "'{name}' is deleted: recover it first (u on the Deleted view)"
                    ));
                }
                let options = self.options()?;
                let storage = (!live.contains(&name))
                    .then(|| self.chosen_storage())
                    .map(|choice| choice.map(|c| (c.storage.clone(), c.label.as_str())));
                let storage = match storage {
                    Some(Some((storage, label))) => Some((storage, label)),
                    Some(None) => Some((SecretStorage::Vault, "the vault")),
                    None => None,
                };
                Ok(new_version_confirm(&name, storage, &options))
            }
        }
    }

    fn submit_edit(
        &self,
        current: &SecretProperties,
        now: OffsetDateTime,
    ) -> Result<Confirm, String> {
        let mut update = UpdateSecretProperties::default();
        let mut lines = vec![format!(
            "Version {} of '{}':",
            current.version,
            output::sanitize(&current.name)
        )];
        for f in &self.fields {
            if f.value.trim() == f.original.trim() {
                continue;
            }
            match f.key {
                FieldKey::Enabled => update.enabled = Some(f.value == "yes"),
                FieldKey::ContentType => update.content_type = Some(content_type(&f.value)),
                FieldKey::Tags => update.tags = Some(tags(&f.value)?),
                FieldKey::NotBefore => update.not_before = Some(time(f.key, &f.value)?),
                FieldKey::Expires => update.expires_on = Some(time(f.key, &f.value)?),
                FieldKey::Name | FieldKey::Storage => {}
            }
            lines.push(format!(
                "  {:<13} {} → {}",
                f.key.label(),
                shown(&f.original),
                shown(&f.value)
            ));
        }
        if update.is_empty() {
            return Err("nothing changed".to_owned());
        }
        let place = &self.kept.place;
        if !self.newest && !self.kept.can(Capability::PerVersionProperties) {
            return Err(format!(
                "{place} keeps these properties for the whole secret, not per version: change \
                 the newest version"
            ));
        }
        if (update.not_before == Some(None) || update.expires_on == Some(None))
            && !self.kept.can(Capability::ClearableTimeWindow)
        {
            return Err(format!(
                "{place} cannot remove a time window: store a new version without one (n)"
            ));
        }
        // The vault's own check, on a copy: a refused update is never sent.
        update.apply(&mut current.clone(), now).map_err(reason)?;
        Ok(Confirm::new(
            "CHANGE VERSION",
            lines,
            Change::Update {
                name: current.name.clone(),
                version: current.version.clone(),
                update,
            },
        ))
    }

    fn options(&self) -> Result<SetSecretOptions, String> {
        let text = |key| self.value(key).map_or("", |f| f.value.as_str());
        let options = SetSecretOptions {
            content_type: content_type(text(FieldKey::ContentType)),
            tags: tags(text(FieldKey::Tags))?,
            enabled: text(FieldKey::Enabled) != "no",
            not_before: time(FieldKey::NotBefore, text(FieldKey::NotBefore))?,
            expires_on: time(FieldKey::Expires, text(FieldKey::Expires))?,
        };
        options.validate().map_err(reason)?;
        if !options.enabled && !self.kept.can(Capability::PerVersionProperties) {
            return Err(format!(
                "{} keeps `enabled` for the whole secret: a new version cannot be stored \
                 disabled",
                self.kept.place
            ));
        }
        Ok(options)
    }
}

/// What a new version, or a new secret's first one, will be. `storage` is
/// where a new secret is created (and how it reads); `None` for a version
/// of a secret the vault has.
fn new_version_confirm(
    name: &str,
    storage: Option<(SecretStorage, &str)>,
    options: &SetSecretOptions,
) -> Confirm {
    let shown_name = output::sanitize(name).into_owned();
    let new_secret = storage.is_some();
    let mut lines = vec![if new_secret {
        format!("A new secret '{shown_name}', its first version:")
    } else {
        format!("A new version of '{shown_name}':")
    }];
    if let Some((_, label)) = &storage {
        lines.push(format!(
            "  {:<13} {}",
            FieldKey::Storage.label(),
            output::sanitize(label)
        ));
    }
    let tags = options
        .tags
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ");
    for (key, value) in [
        (FieldKey::Enabled, yes_no(options.enabled)),
        (
            FieldKey::ContentType,
            options.content_type.clone().unwrap_or_default(),
        ),
        (FieldKey::Tags, tags),
        (FieldKey::NotBefore, time_text(options.not_before)),
        (FieldKey::Expires, time_text(options.expires_on)),
    ] {
        lines.push(format!("  {:<13} {}", key.label(), shown(&value)));
    }
    lines.push(String::new());
    lines.push(
        "Enter leaves the browser for a moment and asks for the value at a hidden prompt, \
         twice. It is stored as typed and never shown."
            .to_owned(),
    );
    Confirm::new(
        if new_secret {
            "NEW SECRET"
        } else {
            "NEW VERSION"
        },
        lines,
        Change::AddVersion {
            name: name.to_owned(),
            options: options.clone(),
            storage: storage.map(|(storage, _)| storage),
        },
    )
}

/// A field's text as a confirmation shows it: `-` for empty.
fn shown(text: &str) -> String {
    let text = text.trim();
    if text.is_empty() {
        "-".to_owned()
    } else {
        output::sanitize(text).into_owned()
    }
}

/// What a refusal says, without its category: a form shows the reason.
fn reason(err: SecretError) -> String {
    match err {
        SecretError::InvalidArgument(why) => why,
        other => other.to_string(),
    }
}

fn content_type(text: &str) -> Option<String> {
    Some(text.trim().to_owned()).filter(|t| !t.is_empty())
}

fn tags(text: &str) -> Result<std::collections::BTreeMap<String, String>, String> {
    let items: Vec<String> = text
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect();
    parse_tags(&items).map_err(|e| e.to_string())
}

fn time(key: FieldKey, text: &str) -> Result<Option<OffsetDateTime>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    timestamp::parse(text)
        .map(Some)
        .map_err(|e| format!("{}: {}", key.label(), reason(e)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sourceorrery_core::RecoveryLevel;

    use super::*;

    fn props() -> SecretProperties {
        let now = timestamp::now();
        SecretProperties {
            vault: "dev".into(),
            name: "db-password".into(),
            version: "0123456789abcdef0123456789abcdef".into(),
            enabled: true,
            content_type: Some("text/plain".into()),
            tags: BTreeMap::from([("env".to_owned(), "dev".to_owned())]),
            not_before: None,
            expires_on: None,
            created_on: now,
            updated_on: now,
            recovery_level: RecoveryLevel::Recoverable,
        }
    }

    fn set(form: &mut Form, key: FieldKey, text: &str) {
        form.focus = form.fields.iter().position(|f| f.key == key).unwrap();
        while !form.fields[form.focus].value.is_empty() {
            form.erase();
        }
        for c in text.chars() {
            form.input(c);
        }
    }

    fn update_of(confirm: &Confirm) -> &UpdateSecretProperties {
        match &confirm.change {
            Change::Update { update, .. } => update,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_untouched_edit_changes_nothing() {
        let form = Form::edit(&props());
        assert_eq!(
            form.submit(timestamp::now()).unwrap_err(),
            "nothing changed"
        );
    }

    #[test]
    fn an_edit_sends_only_what_changed() {
        let mut form = Form::edit(&props());
        set(&mut form, FieldKey::Tags, "env=prod, team=payments");
        set(&mut form, FieldKey::Expires, "2030-01-01T00:00:00Z");
        let confirm = form.submit(timestamp::now()).unwrap();
        let update = update_of(&confirm);
        assert_eq!(update.enabled, None);
        assert_eq!(update.content_type, None);
        assert_eq!(update.not_before, None);
        assert_eq!(
            update.tags.as_ref().map(|t| t.get("team").cloned()),
            Some(Some("payments".to_owned()))
        );
        assert!(update.expires_on.is_some_and(|e| e.is_some()));
        assert!(
            confirm
                .lines
                .iter()
                .any(|l| l.contains("tags") && l.contains("env=dev → env=prod, team=payments"))
        );
    }

    #[test]
    fn clearing_a_field_clears_it() {
        let mut form = Form::edit(&props());
        set(&mut form, FieldKey::ContentType, "");
        set(&mut form, FieldKey::Tags, "");
        let confirm = form.submit(timestamp::now()).unwrap();
        let update = update_of(&confirm);
        assert_eq!(update.content_type, Some(None));
        assert_eq!(update.tags, Some(BTreeMap::new()));
    }

    #[test]
    fn the_enabled_field_switches_and_takes_no_text() {
        let mut form = Form::edit(&props());
        form.focus = 0;
        form.input('x');
        assert_eq!(form.fields[0].value, "yes");
        form.input(' ');
        assert_eq!(form.fields[0].value, "no");
        form.erase();
        assert_eq!(form.fields[0].value, "no");
        form.input('y');
        assert_eq!(form.fields[0].value, "yes");
    }

    #[test]
    fn what_the_vault_would_refuse_is_refused_here() {
        let mut form = Form::edit(&props());
        set(&mut form, FieldKey::Expires, "tomorrow");
        assert!(
            form.submit(timestamp::now())
                .unwrap_err()
                .starts_with("expires:")
        );
        set(&mut form, FieldKey::NotBefore, "2030-06-01T00:00:00Z");
        set(&mut form, FieldKey::Expires, "2030-01-01T00:00:00Z");
        assert!(
            form.submit(timestamp::now()).is_err(),
            "expiry before activation"
        );
        set(&mut form, FieldKey::Expires, "");
        set(&mut form, FieldKey::Tags, "no-equals-sign");
        assert!(
            form.submit(timestamp::now())
                .unwrap_err()
                .contains("key=value")
        );
    }

    #[test]
    fn a_new_version_keeps_the_newest_content_type_and_tags() {
        let form = Form::new_version(&props());
        let confirm = form.submit(timestamp::now()).unwrap();
        let Change::AddVersion {
            name,
            options,
            storage: None,
        } = &confirm.change
        else {
            panic!("{:?}", confirm.change);
        };
        assert_eq!(name, "db-password");
        assert_eq!(options.content_type.as_deref(), Some("text/plain"));
        assert_eq!(options.tags.get("env").map(String::as_str), Some("dev"));
        assert!(options.enabled);
        assert_eq!(confirm.title, "NEW VERSION");
        assert!(confirm.lines.iter().any(|l| l.contains("hidden prompt")));
    }

    #[test]
    fn a_new_secret_needs_a_valid_name_that_is_not_deleted() {
        let mut form = Form::add(vec!["api-key".into()], vec!["old".into()]);
        assert!(form.submit(timestamp::now()).is_err(), "empty name");
        set(&mut form, FieldKey::Name, "not a name!");
        assert!(form.submit(timestamp::now()).is_err());
        set(&mut form, FieldKey::Name, "old");
        assert!(
            form.submit(timestamp::now())
                .unwrap_err()
                .contains("recover it first")
        );
        set(&mut form, FieldKey::Name, "api-key");
        assert_eq!(
            form.submit(timestamp::now()).unwrap().title,
            "NEW VERSION",
            "taken: a version"
        );
        set(&mut form, FieldKey::Name, "stripe-key");
        assert_eq!(form.submit(timestamp::now()).unwrap().title, "NEW SECRET");
    }

    fn kept(place: &str, capabilities: &'static [Capability]) -> Kept {
        Kept {
            place: place.to_owned(),
            capabilities,
        }
    }

    #[test]
    fn a_new_secret_goes_to_the_storage_chosen() {
        let choices = vec![
            StorageChoice {
                label: "SourceOrrery vault".into(),
                storage: SecretStorage::Vault,
                kept: Kept::default(),
            },
            StorageChoice {
                label: "AWS Secrets Manager".into(),
                storage: SecretStorage::Connection("c1".into()),
                kept: kept("AWS Secrets Manager", &[Capability::ClearableTimeWindow]),
            },
        ];
        let mut form = Form::add(vec!["api-key".into()], Vec::new()).storing_in(choices);
        assert_eq!(form.fields[1].key, FieldKey::Storage);
        set(&mut form, FieldKey::Name, "stripe-key");
        form.focus = 1;
        form.input('x');
        assert_eq!(
            form.fields[1].value, "SourceOrrery vault",
            "only space moves it"
        );
        form.input(' ');
        assert_eq!(form.fields[1].value, "AWS Secrets Manager");
        let confirm = form.submit(timestamp::now()).unwrap();
        assert!(
            confirm
                .lines
                .iter()
                .any(|l| l.contains("AWS Secrets Manager"))
        );
        let Change::AddVersion { storage, .. } = &confirm.change else {
            panic!("{:?}", confirm.change);
        };
        assert_eq!(*storage, Some(SecretStorage::Connection("c1".into())));
        // Disabled at birth needs per-version properties.
        form.focus = form
            .fields
            .iter()
            .position(|f| f.key == FieldKey::Enabled)
            .unwrap();
        form.input('n');
        assert!(
            form.submit(timestamp::now())
                .unwrap_err()
                .contains("cannot be stored disabled")
        );
        // A version of a secret the vault has goes where it is.
        form.input('y');
        set(&mut form, FieldKey::Name, "api-key");
        let Change::AddVersion { storage, .. } = form.submit(timestamp::now()).unwrap().change
        else {
            panic!();
        };
        assert_eq!(storage, None);
        // One storage: no field, the vault file.
        let form = Form::add(Vec::new(), Vec::new()).storing_in(vec![StorageChoice {
            label: "SourceOrrery vault".into(),
            storage: SecretStorage::Vault,
            kept: Kept::default(),
        }]);
        assert!(form.fields.iter().all(|f| f.key != FieldKey::Storage));
    }

    #[test]
    fn what_the_storage_cannot_express_is_refused_here() {
        let mut older = Form::edit(&props()).kept_in(kept("AWS Secrets Manager", &[]), false);
        set(&mut older, FieldKey::Tags, "env=prod");
        assert!(
            older
                .submit(timestamp::now())
                .unwrap_err()
                .contains("change the newest version")
        );
        let windowed = SecretProperties {
            expires_on: Some(timestamp::now() + Duration::days(30)),
            ..props()
        };
        let mut form = Form::edit(&windowed).kept_in(
            kept("Azure Key Vault", &[Capability::PerVersionProperties]),
            true,
        );
        set(&mut form, FieldKey::Expires, "");
        assert!(
            form.submit(timestamp::now())
                .unwrap_err()
                .contains("cannot remove a time window")
        );
        // The vault file can.
        let mut form = Form::edit(&windowed);
        set(&mut form, FieldKey::Expires, "");
        assert!(form.submit(timestamp::now()).is_ok());
    }

    #[test]
    fn toggling_says_what_it_does() {
        let confirm = Confirm::toggle(&props());
        assert_eq!(confirm.title, "DISABLE VERSION");
        assert_eq!(update_of(&confirm).enabled, Some(false));
        let disabled = SecretProperties {
            enabled: false,
            ..props()
        };
        assert_eq!(update_of(&Confirm::toggle(&disabled)).enabled, Some(true));
    }

    #[test]
    fn deleting_for_good_must_be_typed() {
        let now = timestamp::now();
        let soft = Confirm::delete("db-password", false, 90, now);
        assert!(soft.ready().is_ok());
        assert!(
            soft.lines
                .iter()
                .any(|l| l.contains("recoverable for 90 days"))
        );

        let mut hard = Confirm::delete("db-password", true, 90, now);
        assert_eq!(hard.title, "DELETE FOR GOOD");
        assert!(hard.ready().is_err());
        for c in "db-passwor".chars() {
            hard.input(c);
        }
        assert!(hard.ready().is_err());
        hard.input('d');
        assert!(hard.ready().is_ok());
        hard.erase();
        assert!(hard.ready().is_err());
    }
}
