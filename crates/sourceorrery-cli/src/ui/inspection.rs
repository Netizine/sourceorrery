//! Cached, value-free text only. Opening this overlay never requests data.
use super::{
    app::{App, Message, Tab},
    viewport::Viewport,
};
#[derive(Debug)]
pub struct Inspection {
    pub title: &'static str,
    pub lines: Vec<String>,
    pub viewport: Viewport,
}
impl Inspection {
    pub fn message(message: &Message) -> Self {
        let (kind, text) = match message {
            Message::Info(t) => ("Note", t),
            Message::Error(t) => ("Error details", t),
        };
        Self {
            title: kind,
            lines: vec![text.clone()],
            viewport: Viewport::default(),
        }
    }
    pub fn metadata(app: &App) -> Option<Self> {
        let mut lines = vec!["Cached metadata — no additional vault/provider reads".into()];
        match app.tab {
            Tab::Secrets | Tab::Deleted => {
                let s = app.session.as_ref()?;
                let p = if app.tab == Tab::Deleted {
                    &app.selected_deleted()?.properties
                } else {
                    app.inspected_version()?
                };
                lines.extend([
                    format!("Vault: {}", p.vault),
                    format!("Name: {}", p.name),
                    format!("Version (full ID): {}", p.version),
                    format!("Reference: {}", p.reference()),
                    format!("Enabled: {}", p.enabled),
                    format!("Created: {}", p.created_on),
                    format!("Updated: {}", p.updated_on),
                    format!("Content type: {}", p.content_type.as_deref().unwrap_or("—")),
                    format!("Not before: {:?}", p.not_before),
                    format!("Expires: {:?}", p.expires_on),
                ]);
                for (k, v) in &p.tags {
                    lines.push(format!("Tag {k}={v}"));
                }
                if let Some(c) = s.connection_of(&p.name) {
                    lines.push(format!(
                        "Storage: {} · {} · {:?}",
                        c.settings.provider().display_name(),
                        c.id,
                        c.settings
                    ));
                } else {
                    lines.push("Storage: vault".into());
                }
                for project in s.projects_using(&p.name) {
                    lines.push(format!(
                        "Project: {} · {}",
                        project.link.name,
                        project.link.path.display()
                    ));
                }
            }
            Tab::Projects => {
                let p = app.project_detail().or_else(|| app.selected_project())?;
                lines.extend([
                    format!("Project: {}", p.link.name),
                    format!("Full ID: {}", p.link.id),
                    format!("Path: {}", p.link.path.display()),
                    format!("Recorded: {}", p.link.linked_on),
                    format!("Manifest: {:?}", p.status),
                ]);
            }
            Tab::Audit => {
                let e = *app
                    .shown_events()
                    .get(app.list(Tab::Audit).table.selected()?)?;
                lines.extend([
                    format!("Event: {}", e.id),
                    format!("Time: {}", e.occurred_on),
                    format!("Actor: {}", e.actor),
                    format!("Operation: {}", e.operation.as_str()),
                    format!("Secret: {}", e.secret_name.as_deref().unwrap_or("—")),
                    format!("Version: {}", e.version.as_deref().unwrap_or("—")),
                    format!("Outcome: {}", e.outcome.as_str()),
                    format!("Detail: {}", e.detail.as_deref().unwrap_or("—")),
                ]);
            }
            Tab::Vaults => {
                let v = app.selected_vault()?;
                lines.extend([
                    format!("Vault: {}", v.name),
                    format!("Path: {}", v.path.display()),
                    format!("Size: {:?}", v.size),
                    format!("Modified: {:?}", v.modified),
                ]);
            }
            Tab::Overview => return None,
        }
        Some(Self {
            title: "Inspect metadata",
            lines,
            viewport: Viewport::default(),
        })
    }
}
