//! Synchronous feedback and freshness of explicit loads; never a scheduler.
use std::{fmt::Write as _, time::Duration};
use time::{OffsetDateTime, macros::format_description};
#[derive(Debug, Default)]
pub struct Feedback {
    pub at: Option<OffsetDateTime>,
    pub failed: bool,
    pub partial: bool,
    pub operation: Option<&'static str>,
    pub elapsed: Option<Duration>,
}
impl Feedback {
    pub fn loaded(&mut self, at: OffsetDateTime, partial: bool) {
        self.at = Some(at);
        self.failed = false;
        self.partial = partial;
    }
    pub fn label(&self) -> String {
        if let Some(operation) = self.operation {
            return format!("{operation} (synchronous)");
        }
        let Some(at) = self.at else {
            return String::new();
        };
        let at = at
            .format(format_description!("[hour]:[minute]"))
            .unwrap_or_default();
        if self.failed {
            return format!("Refresh failed — last successful load {at} UTC");
        }
        let mut text = format!("Snapshot from {at} UTC");
        if self.partial {
            text.push_str(" · Warning: provider metadata incomplete");
        }
        if let Some(elapsed) = self.elapsed {
            let _ = write!(text, " · last operation {}ms", elapsed.as_millis());
        }
        text
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_refresh_never_advances_snapshot_time_and_warning_is_explicit() {
        let at = OffsetDateTime::UNIX_EPOCH;
        let mut f = Feedback::default();
        f.loaded(at, false);
        f.failed = true;
        assert_eq!(f.at, Some(at));
        assert!(f.label().contains("Refresh failed"));
        f.loaded(at, true);
        assert!(f.label().contains("Warning"));
    }
}
