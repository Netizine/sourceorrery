//! A QR code drawn in the terminal with half-block characters, two module
//! rows per text line, with one module of quiet zone: the setup screen
//! keeps blank cells around the code, which give the rest of the zone the
//! standard asks for, and the code then fits a 24-line terminal. Used to
//! show an authenticator enrolment; the text encoded is the caller's to
//! guard.

use anyhow::anyhow;
use qrcode::{EcLevel, QrCode};

/// Modules of quiet zone around the code.
const QUIET: usize = 1;

/// `text` as a QR code, one `String` per terminal line, dark modules as
/// block characters on the terminal's background. Most authenticator apps
/// read a code in either polarity; a user whose camera cannot is offered
/// the text itself by the caller.
pub fn render(text: &str) -> anyhow::Result<Vec<String>> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)
        .map_err(|err| anyhow!("cannot encode a QR code: {err}"))?;
    let width = code.width();
    let modules = code.to_colors();
    let dark = |x: isize, y: isize| -> bool {
        if x < 0 || y < 0 {
            return false;
        }
        let (x, y) = (x.unsigned_abs(), y.unsigned_abs());
        x < width && y < width && modules[y * width + x] == qrcode::Color::Dark
    };
    let span = isize::try_from(width + 2 * QUIET).unwrap_or(isize::MAX);
    let offset = isize::try_from(QUIET).unwrap_or(0);
    let mut lines = Vec::with_capacity(width / 2 + QUIET + 1);
    let mut y = -offset;
    while y < span - offset {
        let mut line = String::with_capacity(width + 2 * QUIET);
        for x in -offset..span - offset {
            let top = dark(x, y);
            let bottom = dark(x, y + 1);
            line.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        lines.push(line);
        y += 2;
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_square_with_a_quiet_zone() {
        let lines = render("otpauth://totp/SourceOrrery:dev?secret=MZXW6YTBOI&issuer=SourceOrrery")
            .unwrap();
        let code = QrCode::with_error_correction_level(
            b"otpauth://totp/SourceOrrery:dev?secret=MZXW6YTBOI&issuer=SourceOrrery",
            EcLevel::M,
        )
        .unwrap();
        let width = code.width() + 2 * QUIET;
        assert_eq!(lines.len(), width.div_ceil(2));
        assert!(lines.iter().all(|l| l.chars().count() == width));
        // A blank module round the code: the first column, and the top half
        // of the first line, whose bottom half is the finder pattern's edge.
        assert!(lines.iter().all(|l| l.starts_with(' ')));
        assert!(lines[0].starts_with(" ▄▄▄▄▄▄▄"), "{}", lines[0]);
        assert!(lines[1].starts_with(" █"), "{}", lines[1]);
        assert!(lines.iter().any(|l| l.contains('▀') || l.contains('▄')));
    }
}
