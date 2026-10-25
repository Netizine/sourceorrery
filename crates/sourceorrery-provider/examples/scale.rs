//! How the vault's costs grow with its history and its secrets (B29).
//!
//! ```text
//! cargo run --release -p sourceorrery-provider --example scale -- \
//!     --secrets 100 --events 10000 [--runs 15] [--threads 4] [--dir DIR]
//! ```
//!
//! Builds a vault with `--secrets` secrets and at least `--events` audit
//! events (reads, each of which records one), then times each operation a
//! CLI command or an SDK makes, `--runs` times, and prints one Markdown row
//! per operation: median, 90th percentile and slowest, in milliseconds.
//! Synthetic values only; the vault opens with its recovery key and no
//! credential store. With `--dir` the vault is kept (and reused when the
//! same file is asked for again), so a large history is built once.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sourceorrery_core::audit::AuditQuery;
use sourceorrery_core::{SecretBytes, SecretClient, SetSecretOptions};
use sourceorrery_provider::Routed;
use sourceorrery_storage::{CreateVaultOptions, NoStore, SqliteVault, StaticRecoveryKey};

struct Args {
    secrets: usize,
    events: u64,
    runs: usize,
    threads: usize,
    dir: Option<PathBuf>,
}

fn args() -> Args {
    let mut args = Args {
        secrets: 100,
        events: 1000,
        runs: 15,
        threads: 4,
        dir: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--secrets" => args.secrets = value.parse().expect("--secrets"),
            "--events" => args.events = value.parse().expect("--events"),
            "--runs" => args.runs = value.parse().expect("--runs"),
            "--threads" => args.threads = value.parse().expect("--threads"),
            "--dir" => args.dir = Some(PathBuf::from(value)),
            other => panic!("unknown flag {other}"),
        }
    }
    args
}

fn open(path: &Path, key: &str) -> SqliteVault {
    SqliteVault::open(path, Arc::new(NoStore), &StaticRecoveryKey::new(key)).expect("open")
}

fn name(i: usize) -> String {
    format!("secret-{i:06}")
}

/// The vault at `dir`, built to `secrets` secrets and `events` audit events
/// unless it already is; returns its path and recovery key.
fn fixture(dir: &Path, secrets: usize, events: u64) -> (PathBuf, String) {
    let path = dir.join(format!("scale-{secrets}-{events}.sorvault"));
    let key_file = path.with_extension("key");
    if path.is_file() && key_file.is_file() {
        return (path, std::fs::read_to_string(key_file).expect("key"));
    }
    let started = Instant::now();
    let created = SqliteVault::create(
        &path,
        "scale",
        CreateVaultOptions::default(),
        Arc::new(NoStore),
    )
    .expect("create");
    let key = created.recovery_key.as_str().to_owned();
    let vault = created.vault;
    for i in 0..secrets {
        let value = SecretBytes::new(format!("synthetic-value-{i:06}").into_bytes());
        vault
            .set_secret(&name(i), value, SetSecretOptions::default())
            .expect("set");
    }
    let mut rows = vault.verify_audit_chain().expect("verify").rows;
    let mut i = 0;
    while rows < events {
        vault.get_secret(&name(i % secrets), None).expect("get");
        i += 1;
        rows += 1;
    }
    drop(vault);
    std::fs::write(&key_file, &key).expect("write key");
    eprintln!(
        "built {} with {secrets} secrets and {rows} events in {:.1}s",
        path.display(),
        started.elapsed().as_secs_f64()
    );
    (path, key)
}

fn time(runs: usize, mut op: impl FnMut()) -> Vec<Duration> {
    let mut samples: Vec<Duration> = (0..runs)
        .map(|_| {
            let started = Instant::now();
            op();
            started.elapsed()
        })
        .collect();
    samples.sort();
    samples
}

fn row(op: &str, samples: &[Duration]) {
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let at = |percent: usize| {
        // Nearest rank: the sample at or above the percentile.
        let rank = (samples.len() * percent)
            .div_ceil(100)
            .clamp(1, samples.len());
        samples[rank - 1]
    };
    println!(
        "| {op} | {:.2} | {:.2} | {:.2} |",
        ms(at(50)),
        ms(at(90)),
        ms(*samples.last().expect("a sample"))
    );
}

/// Separate handles, as separate processes would have, each reading in a
/// loop while the others do.
fn contention(path: &Path, key: &str, threads: usize, per: usize) {
    let started = Instant::now();
    let workers: Vec<_> = (0..threads)
        .map(|t| {
            let (path, key) = (path.to_path_buf(), key.to_owned());
            std::thread::spawn(move || {
                let vault = open(&path, &key);
                let name = name(t % 2);
                time(per, || {
                    vault.get_secret(&name, None).expect("get under contention");
                })
            })
        })
        .collect();
    let mut all: Vec<Duration> = workers
        .into_iter()
        .flat_map(|w| w.join().expect("worker"))
        .collect();
    all.sort();
    row(
        &format!("get_secret, {threads} handles at once ({per} each)"),
        &all,
    );
    eprintln!(
        "contention wall time {:.1} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );
}

/// The audit log: the newest events, a follow poll, all of it, its
/// verification, and an export of the vault.
fn audit_log(vault: &SqliteVault, runs: usize, scratch: &Path) {
    row(
        "audit_events (newest 100)",
        &time(runs, || {
            vault
                .audit_events(AuditQuery {
                    limit: Some(100),
                    ..AuditQuery::default()
                })
                .expect("audit");
        }),
    );
    let newest = vault
        .audit_events(AuditQuery {
            limit: Some(1),
            ..AuditQuery::default()
        })
        .expect("audit")[0]
        .occurred_on;
    row(
        "audit_events (follow poll: since the newest)",
        &time(runs, || {
            vault
                .audit_events(AuditQuery {
                    since: Some(newest),
                    limit: Some(usize::MAX),
                    ..AuditQuery::default()
                })
                .expect("audit");
        }),
    );
    row(
        "audit_events (export: everything)",
        &time(runs.min(5), || {
            vault
                .audit_events(AuditQuery {
                    limit: Some(usize::MAX),
                    ..AuditQuery::default()
                })
                .expect("audit");
        }),
    );
    row(
        "verify_audit_chain",
        &time(runs.min(5), || {
            vault.verify_audit_chain().expect("verify");
        }),
    );
    let mut copy = 0;
    row(
        "export_to (a copy for another machine)",
        &time(runs.min(5), || {
            copy += 1;
            let out = scratch.join(format!("export-{copy}.sorvault"));
            vault.export_to(&out).expect("export");
            std::fs::remove_file(out).expect("remove");
        }),
    );
}

fn main() {
    let args = args();
    let scratch = tempfile::tempdir().expect("tempdir");
    let dir = args
        .dir
        .clone()
        .unwrap_or_else(|| scratch.path().to_path_buf());
    std::fs::create_dir_all(&dir).expect("dir");
    let (path, key) = fixture(&dir, args.secrets, args.events);
    let vault = open(&path, &key);
    let before = vault.verify_audit_chain().expect("verify").rows;
    println!(
        "\n{} secrets, {before} audit events, {} runs each\n",
        args.secrets, args.runs
    );
    println!("| operation | median ms | p90 ms | max ms |");
    println!("|---|---|---|---|");
    drop(vault);

    row(
        "open (unlock, chain walk)",
        &time(args.runs, || drop(open(&path, &key))),
    );
    let vault = open(&path, &key);
    let first = name(0);
    row(
        "get_secret",
        &time(args.runs, || {
            vault.get_secret(&first, None).expect("get");
        }),
    );
    row(
        "get_secret_properties",
        &time(args.runs, || {
            vault
                .get_secret_properties(&first, None)
                .expect("properties");
        }),
    );
    row(
        "list_properties_of_secrets (all)",
        &time(args.runs, || {
            vault.list_properties_of_secrets().expect("list");
        }),
    );
    row(
        "list_properties_of_secret_versions",
        &time(args.runs, || {
            vault
                .list_properties_of_secret_versions(&first)
                .expect("versions");
        }),
    );
    audit_log(&vault, args.runs, scratch.path());
    let routed = Routed::new(vault);
    row(
        "Routed get_secret (the CLI's and the SDKs' path)",
        &time(args.runs, || {
            routed.get_secret(&first, None).expect("get");
        }),
    );
    row(
        "Routed list_properties_of_secrets",
        &time(args.runs, || {
            routed.list_properties_of_secrets().expect("list");
        }),
    );
    drop(routed);
    contention(&path, &key, args.threads, args.runs.max(10));
}
