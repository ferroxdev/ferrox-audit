//! Never probe a clipboard: running a candidate to test it rewrites it, so only spawn errors tell absence from failure.

use std::io::{ErrorKind, Write};
use std::process::{Command, Stdio};

/// Why a copy did not happen.
#[derive(Debug)]
pub enum Unavailable {
    /// No candidate exists on this machine.
    NoneFound,
    /// A candidate existed and refused.
    Failed(String),
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoneFound => {
                #[cfg(windows)]
                f.write_str("no clipboard program found (tried clip)")?;
                #[cfg(not(windows))]
                f.write_str("no clipboard program found (tried pbcopy, wl-copy, xclip, xsel)")?;
                Ok(())
            }
            Self::Failed(reason) => write!(f, "no clipboard program accepted the text: {reason}"),
        }
    }
}

impl std::error::Error for Unavailable {}

/// Programs tried in order, with the arguments that put stdin on the clipboard.
#[cfg(not(windows))]
const CANDIDATES: &[(&str, &[&str])] = &[
    ("pbcopy", &[]),
    ("wl-copy", &[]),
    ("xclip", &["-selection", "clipboard", "-in"]),
    ("xsel", &["--clipboard", "--input"]),
];

/// Windows: `clip` reads the clipboard from stdin, same idea as `pbcopy`.
#[cfg(windows)]
const CANDIDATES: &[(&str, &[&str])] = &[("clip", &[])];

/// Copy `text` to the clipboard.
pub fn copy(text: &str) -> Result<(), Unavailable> {
    let mut refusal = None;
    for (program, args) in CANDIDATES {
        match write(program, args, text) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => refusal = Some(format!("{program}: {error}")),
        }
    }
    Err(match refusal {
        Some(reason) => Unavailable::Failed(reason),
        None => Unavailable::NoneFound,
    })
}

/// Feed text to stdin; a `NotFound` spawn means absence, anything else a refusal.
fn write(program: &str, args: &[&str], text: &str) -> std::io::Result<()> {
    let mut child = Command::new(program)
        .args(args.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut pipe) = child.stdin.take() {
        if let Err(error) = pipe.write_all(text.as_bytes()) {
            drop(pipe);
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    }
    if child.wait()?.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("{program} exited non-zero")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_program_is_reported_as_missing_and_does_not_stop_the_search() {
        let error = write("ferrox-no-such-clipboard-program", &[], "text").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
    }

    #[test]
    #[cfg(not(windows))]
    fn a_program_that_exits_non_zero_is_a_refusal_not_an_absence() {
        // `false` exists on every platform here and always exits 1 — what a broken clipboard program looks like.
        let error = write("false", &[], "text").unwrap_err();
        assert_ne!(error.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn the_failure_message_names_what_was_tried() {
        let expected = if cfg!(windows) { "clip" } else { "pbcopy" };
        assert!(Unavailable::NoneFound.to_string().contains(expected));
    }
}
