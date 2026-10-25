//! Projects (ADR 0009, section 6): the folders whose `sourceorrery.toml`
//! was built from this vault, recorded by `init`. The vault keeps each as a
//! path and a project name, sealed under the vault key and bound to the
//! vault and the record (a folder name can say more than a secret name),
//! with a keyed MAC of the path so that a folder is recorded once. The
//! manifest at that path is the source of the project's secrets, so a hand
//! edit never drifts from the vault.
//!
//! Each row carries a tag over its fields, and the settings record lists
//! every row with that tag, as it does connections: an edited row is
//! refused when it is read, and a row added, removed or replaced by an older
//! copy is refused at unlock. Linking is audited as `project_link`,
//! unlinking as `project_unlink`; the detail names the record's id, never
//! its path or name.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};
use serde::Serialize;
use sourceorrery_core::audit::{AuditOperation, AuditOutcome};
use sourceorrery_core::{Result, SecretError, timestamp};
use sourceorrery_crypto::random;
use time::OffsetDateTime;

use super::SqliteVault;
use super::schema::{Meta, crypto, db, from_nanos, integrity_error, nanos, write_settings_tag};
use crate::integrity::{self, ProjectFields};

/// The longest project name, in characters.
pub const MAX_PROJECT_NAME_LEN: usize = 128;

/// The longest project path, in bytes.
const MAX_PATH_LEN: usize = 4096;

/// A project folder the vault records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProjectLink {
    /// The record's id in this vault.
    pub id: String,
    /// The folder, as it was recorded.
    pub path: PathBuf,
    /// The project's name, as its manifest gives it.
    pub name: String,
    /// When the folder was first recorded.
    #[serde(with = "time::serde::rfc3339")]
    pub linked_on: OffsetDateTime,
}

/// AAD binding a project's sealed path and name to their vault and record.
fn project_aad(vault_id: &str, id: &str) -> String {
    format!("sourceorrery/v4/project/{vault_id}/{id}")
}

fn corrupt(id: &str) -> SecretError {
    SecretError::Storage(format!("corrupt project {id}"))
}

fn no_such(id: &str) -> SecretError {
    SecretError::InvalidArgument(format!("the vault has no project '{id}'"))
}

/// A `projects` row as stored.
struct ProjectRow {
    id: String,
    path_mac: Vec<u8>,
    sealed: String,
    linked_on: i64,
    tag: Vec<u8>,
}

impl ProjectRow {
    fn fields<'a>(&'a self, vault_id: &'a str) -> ProjectFields<'a> {
        ProjectFields {
            vault_id,
            id: &self.id,
            path_mac: &self.path_mac,
            sealed: &self.sealed,
            linked_on: self.linked_on,
        }
    }
}

/// Every `projects` row, oldest first.
fn read_rows(conn: &Connection) -> Result<Vec<ProjectRow>> {
    conn.prepare("SELECT id, path_mac, sealed, linked_on, tag FROM projects ORDER BY linked_on, id")
        .map_err(db)?
        .query_map([], |row| {
            Ok(ProjectRow {
                id: row.get(0)?,
                path_mac: row.get(1)?,
                sealed: row.get(2)?,
                linked_on: row.get(3)?,
                tag: row.get(4)?,
            })
        })
        .map_err(db)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db)
}

/// The plaintext sealed for a project: its path, then its name, each as a
/// big-endian `u32` length and its bytes.
fn encode(path: &str, name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + path.len() + name.len());
    for part in [path, name] {
        // Both are bounded far below `u32::MAX` by the checks before.
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part.as_bytes());
    }
    out
}

/// The path and name [`encode`] encoded, or `None` for bytes it cannot
/// have written.
fn decode(plain: &[u8]) -> Option<(String, String)> {
    let mut parts = Vec::with_capacity(2);
    let mut rest = plain;
    while !rest.is_empty() {
        let (len, tail) = rest.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
        if tail.len() < len {
            return None;
        }
        let (part, tail) = tail.split_at(len);
        parts.push(String::from_utf8(part.to_vec()).ok()?);
        rest = tail;
    }
    let [path, name]: [String; 2] = parts.try_into().ok()?;
    Some((path, name))
}

/// A project name: 1 to [`MAX_PROJECT_NAME_LEN`] characters, one line.
fn check_name(name: &str) -> Result<()> {
    if name.trim().is_empty()
        || name.chars().count() > MAX_PROJECT_NAME_LEN
        || name.chars().any(char::is_control)
    {
        return Err(SecretError::InvalidArgument(format!(
            "a project name is one line of 1 to {MAX_PROJECT_NAME_LEN} characters"
        )));
    }
    Ok(())
}

/// The path of a project folder as recorded: absolute, UTF-8, at most
/// [`MAX_PATH_LEN`] bytes and without control characters. The caller gives
/// it in the form it compares folders by (canonical, say): the vault
/// records it as given.
fn path_text(path: &Path) -> Result<&str> {
    let text = path.to_str().ok_or_else(|| {
        SecretError::InvalidArgument("a project folder's path must be valid UTF-8".to_owned())
    })?;
    if !path.is_absolute() {
        return Err(SecretError::InvalidArgument(
            "a project folder's path must be absolute".to_owned(),
        ));
    }
    if text.len() > MAX_PATH_LEN || text.chars().any(char::is_control) {
        return Err(SecretError::InvalidArgument(format!(
            "a project folder's path is at most {MAX_PATH_LEN} bytes, without control characters"
        )));
    }
    Ok(text)
}

impl SqliteVault {
    /// The project rows `meta` lists, each with the tag it lists and a tag
    /// that verifies; a row edited, added or left out is refused.
    fn listed_projects(&self, conn: &Connection, meta: &Meta) -> Result<Vec<ProjectRow>> {
        let rows = read_rows(conn)?;
        if rows.len() != meta.projects.len() {
            return Err(integrity_error("the vault's projects"));
        }
        for row in &rows {
            let listed = meta
                .projects
                .iter()
                .any(|(id, tag)| *id == row.id && *tag == row.tag);
            if !listed
                || !integrity::verify_project_tag(
                    &self.metadata_key,
                    &row.fields(&self.meta.id),
                    Some(&row.tag),
                )
            {
                return Err(integrity_error(&format!("project {}", row.id)));
            }
        }
        Ok(rows)
    }

    /// The link `row` records: its sealed path and name, opened, with the
    /// path's MAC checked against the row's.
    fn project_link(&self, row: &ProjectRow) -> Result<ProjectLink> {
        let plain =
            self.unseal_bound(&project_aad(&self.meta.id, &row.id), &row.sealed, "project")?;
        let (path, name) = decode(&plain).ok_or_else(|| corrupt(&row.id))?;
        let mac = integrity::project_path_mac(&self.metadata_key, &self.meta.id, &path);
        if mac.as_slice() != row.path_mac.as_slice() {
            return Err(corrupt(&row.id));
        }
        Ok(ProjectLink {
            id: row.id.clone(),
            path: PathBuf::from(path),
            name,
            linked_on: from_nanos(row.linked_on)?,
        })
    }

    /// Tag `row` and write it, updating the row with its id in place.
    fn write_project(&self, conn: &Connection, row: &mut ProjectRow) -> Result<()> {
        row.tag = integrity::project_tag(&self.metadata_key, &row.fields(&self.meta.id)).to_vec();
        conn.execute(
            "INSERT INTO projects (id, path_mac, sealed, linked_on, tag)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET path_mac = excluded.path_mac,
                 sealed = excluded.sealed, linked_on = excluded.linked_on, tag = excluded.tag",
            params![row.id, row.path_mac, row.sealed, row.linked_on, row.tag],
        )
        .map_err(db)?;
        Ok(())
    }

    /// Change the projects in one transaction that passes the checks every
    /// operation passes: `change` gets the verified rows, writes what it
    /// changes and returns the result with the audit detail. The settings
    /// record then covers the rows as they are. A refusal is audited as a
    /// failure and nothing is written.
    fn change_projects<T>(
        &self,
        operation: AuditOperation,
        change: impl FnOnce(&Connection, Vec<ProjectRow>) -> Result<(T, String)>,
    ) -> Result<T> {
        let mut conn = self.lock()?;
        let tx = self.begin(&mut conn, operation)?;
        let changed = self.verified_meta(&tx).and_then(|meta| {
            let rows = self.listed_projects(&tx, &meta)?;
            let changed = change(&tx, rows)?;
            let tag = write_settings_tag(&tx, &self.metadata_key, &meta)?;
            Ok((changed, tag))
        });
        let ((value, detail), tag) = match changed {
            Ok(changed) => changed,
            Err(err) => return self.fail(tx, operation, None, None, err),
        };
        self.audit_settings(&tx, operation, AuditOutcome::Success, &detail, tag)?;
        tx.commit().map_err(db)?;
        Ok(value)
    }

    /// The project folders the vault records, oldest first. Not audited,
    /// like the connections: it is the vault's record of where it is used,
    /// read where the vault is already open for its owner.
    pub fn projects(&self) -> Result<Vec<ProjectLink>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().map_err(db)?;
        let meta = self.verified_meta(&tx)?;
        self.listed_projects(&tx, &meta)?
            .iter()
            .map(|row| self.project_link(row))
            .collect()
    }

    /// Record the folder at `path` as the project `name` (see
    /// `path_text` for what the path must be). A folder recorded already
    /// keeps its id and the day it was first recorded, and takes the new
    /// name. Audited as `project_link`.
    pub fn link_project(&self, path: &Path, name: &str) -> Result<ProjectLink> {
        self.change_projects(AuditOperation::ProjectLink, |conn, rows| {
            let text = path_text(path)?;
            check_name(name)?;
            let mac = integrity::project_path_mac(&self.metadata_key, &self.meta.id, text);
            let (mut row, detail) =
                if let Some(row) = rows.into_iter().find(|row| row.path_mac == mac) {
                    let current = self.project_link(&row)?;
                    if current.name == name {
                        return Ok((current, format!("project {} linked already", row.id)));
                    }
                    let sealed =
                        self.seal_bound(&project_aad(&self.meta.id, &row.id), &encode(text, name))?;
                    let detail = format!("project {} renamed", row.id);
                    (ProjectRow { sealed, ..row }, detail)
                } else {
                    let id = random::random_hex(8).map_err(crypto)?;
                    let sealed =
                        self.seal_bound(&project_aad(&self.meta.id, &id), &encode(text, name))?;
                    let detail = format!("project {id} linked");
                    let row = ProjectRow {
                        path_mac: mac.to_vec(),
                        sealed,
                        linked_on: nanos(timestamp::now())?,
                        tag: Vec::new(),
                        id,
                    };
                    (row, detail)
                };
            self.write_project(conn, &mut row)?;
            Ok((self.project_link(&row)?, detail))
        })
    }

    /// Remove the record of the project `id`; the folder and its manifest
    /// are not touched. Audited as `project_unlink`.
    pub fn unlink_project(&self, id: &str) -> Result<()> {
        self.change_projects(AuditOperation::ProjectUnlink, |conn, rows| {
            if !rows.iter().any(|row| row.id == id) {
                return Err(no_such(id));
            }
            conn.execute("DELETE FROM projects WHERE id = ?1", params![id])
                .map_err(db)?;
            Ok(((), format!("project {id} unlinked")))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sealed_record_round_trips_and_nothing_else_decodes() {
        let plain = encode("/home/me/app", "my-app");
        assert_eq!(
            decode(&plain),
            Some(("/home/me/app".to_owned(), "my-app".to_owned()))
        );
        let mut extra = plain.clone();
        extra.extend_from_slice(&[0, 0, 0, 1, b'x']);
        for bad in [
            &[][..],
            &plain[..plain.len() - 1],
            &extra[..],
            &encode("/only", "")[..8],
            &[0, 0, 0, 2, 0xff, 0xfe, 0, 0, 0, 0][..],
        ] {
            assert!(decode(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn names_and_paths_are_checked() {
        check_name("my-app").unwrap();
        check_name("Mon application").unwrap();
        for bad in [
            "",
            "  ",
            "two\nlines",
            &"n".repeat(MAX_PROJECT_NAME_LEN + 1),
        ] {
            assert_eq!(check_name(bad).unwrap_err().code(), "invalid_argument");
        }
        let absolute = std::env::temp_dir().join("app");
        assert_eq!(path_text(&absolute).unwrap(), absolute.to_str().unwrap());
        for bad in [Path::new("relative/app"), Path::new("app")] {
            assert_eq!(path_text(bad).unwrap_err().code(), "invalid_argument");
        }
        let control = std::env::temp_dir().join("a\u{1b}b");
        assert_eq!(path_text(&control).unwrap_err().code(), "invalid_argument");
    }
}
