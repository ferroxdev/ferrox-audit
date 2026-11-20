//! The parse is the contract: unforgiving about shape — one fenced block per section, unknown fields warn — never judging prose.

use std::fmt;
use std::path::{Path, PathBuf};

/// How much a diagnostic should stop you.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Renders and advises anyway.
    Warning,
    /// Blocks rendering, and `check` exits non-zero.
    Error,
}

/// One thing wrong with the library, located in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// `Warning` or `Error`.
    pub severity: Severity,
    /// 1-based line in the library, or 0 when the problem is the file as a whole.
    pub line: usize,
    /// What is wrong, and what to do about it where that is knowable.
    pub message: String,
}

impl Diagnostic {
    /// A problem that blocks rendering.
    pub fn error(line: usize, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            line,
            message: message.into(),
        }
    }

    /// A problem that is worth reporting but not worth stopping for.
    pub fn warning(line: usize, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "{}", self.message)
        } else {
            write!(f, "line {}: {}", self.line, self.message)
        }
    }
}

/// Where a prompt is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Open and not started. The only status the advisor picks from.
    Todo,
    /// Open and started: finish it before a new slice starts, so ranking skips it.
    Doing,
    /// Finished. Unblocks whatever depends on it.
    Done,
    /// Open, waiting on something outside the roadmap — a decision, a dependency, a person.
    Blocked,
}

impl Status {
    /// Every spelling accepted in `**Status:**`, for error messages.
    pub const NAMES: &'static [&'static str] = &["todo", "doing", "done", "blocked"];

    /// Parse a status, or `None` if the spelling is not one of [`Status::NAMES`].
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "todo" => Some(Self::Todo),
            "doing" => Some(Self::Doing),
            "done" => Some(Self::Done),
            "blocked" => Some(Self::Blocked),
            _ => None,
        }
    }

    /// The spelling used in the library.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Todo => "todo",
            Self::Doing => "doing",
            Self::Done => "done",
            Self::Blocked => "blocked",
        }
    }

    /// `Blocked` counts as open: an outside decision does not finish the slice.
    pub fn is_open(self) -> bool {
        !matches!(self, Self::Done)
    }
}

/// How much work a prompt is; ordered smallest-first because that is the advisor's tie-break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effort {
    /// Hours.
    Small,
    /// A day or two.
    Medium,
    /// Longer than a sitting, and therefore worth splitting before starting.
    Large,
}

impl Effort {
    /// Every spelling accepted in `**Effort:**`, for error messages.
    pub const NAMES: &'static [&'static str] = &["small", "medium", "large"];

    /// Parse an effort, or `None` if the spelling is not one of [`Effort::NAMES`].
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "small" => Some(Self::Small),
            "medium" => Some(Self::Medium),
            "large" => Some(Self::Large),
            _ => None,
        }
    }

    /// The spelling used in the library.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
        }
    }
}

/// Which matrix rows a template draws; absent means [`Targets::None`], so a forgotten field is visible, not defaulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Targets {
    /// Rows the matrix marks as not yet implemented.
    Open,
    /// Rows the matrix marks as implemented.
    Implemented,
    /// Every method row, open or shipped.
    All,
    /// Not a matrix template.
    None,
}

impl Targets {
    /// Every spelling accepted in `**Targets:**`, for error messages.
    pub const NAMES: &'static [&'static str] = &["open", "implemented", "all", "none"];

    /// Parse a target class, or `None` if the spelling is not one of [`Targets::NAMES`].
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "open" => Some(Self::Open),
            "implemented" => Some(Self::Implemented),
            "all" => Some(Self::All),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    /// The spelling used in the library.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Implemented => "implemented",
            Self::All => "all",
            Self::None => "none",
        }
    }

    /// Whether this prompt draws its target from the matrix rather than being a fixed slice.
    pub fn is_matrix(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// An extra instruction that extends one prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addon {
    /// The name as written in the library.
    pub title: String,
    /// The name as typed on the command line: lowercase, `-` between words.
    pub slug: String,
    /// One line of instruction.
    pub body: String,
}

impl Addon {
    /// `title (body)` for a listing.
    pub fn describe(&self) -> String {
        format!("{}: {}", self.slug, self.body)
    }
}

/// A file a prompt edits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Touch {
    /// A file that must exist. `check` fails when it does not.
    Existing(String),
    /// A file this prompt creates (`+path`); `check` fails when it exists — work done or misfiled.
    Created(String),
}

impl Touch {
    /// The path, without the `+`.
    pub fn path(&self) -> &str {
        match self {
            Self::Existing(path) | Self::Created(path) => path,
        }
    }

    /// Whether this prompt claims the file.
    pub fn claims_existing_file(&self) -> bool {
        matches!(self, Self::Existing(_))
    }
}

/// One `{name}` or `{name=default}` in a prompt body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder {
    /// The name given on the command line.
    pub name: String,
    /// The library's default; `None` means a decision this tool refuses to make.
    pub default: Option<String>,
}

/// One prompt: a slice of work, and the conditions under which it is done.
#[derive(Debug, Clone)]
pub struct Prompt {
    /// Stable, never renumbered: other prompts cite it in `**Depends on:**`.
    pub id: u32,
    /// The title after the number.
    pub title: String,
    /// The situation that calls for this prompt.
    pub when_to_use: String,
    /// Where it is in its life.
    pub status: Status,
    /// How much it moves the rest of the roadmap, 1-5.
    pub leverage: u8,
    /// How much work it is.
    pub effort: Effort,
    /// The checks that must pass, printed verbatim.
    pub gates: Vec<String>,
    /// Prompts that must be `done` first.
    pub depends_on: Vec<u32>,
    /// Files it edits.
    pub touches: Vec<Touch>,
    /// Its weight in `--rotate` draws. Zero excludes it.
    pub random_weight: u32,
    /// Which matrix rows this template draws its target from, if any.
    pub targets: Targets,
    /// A rule that applies to this prompt alone, layered under the shared one.
    pub protocol: String,
    /// The prompt itself, placeholders intact.
    pub body: String,
    /// Extra instructions, in library order.
    pub addons: Vec<Addon>,
    /// Placeholders in the body and add-ons, in first-appearance order.
    pub placeholders: Vec<Placeholder>,
    /// Line of the heading, for messages.
    pub line: usize,
}

impl Prompt {
    /// Whether the advisor may offer this prompt.
    pub fn is_open(&self) -> bool {
        self.status.is_open()
    }

    /// The add-on with this slug.
    pub fn addon(&self, slug: &str) -> Option<&Addon> {
        self.addons.iter().find(|addon| addon.slug == slug)
    }

    /// Placeholders with no default: the values only a contributor can supply.
    pub fn required_inputs(&self) -> impl Iterator<Item = &str> {
        self.required_inputs_for(&self.addons)
    }

    /// Required placeholders the selected add-ons actually reach, so an add-on that was not
    /// chosen cannot keep a handout from being rendered.
    pub fn required_inputs_for<'a>(
        &'a self,
        addons: &'a [Addon],
    ) -> impl Iterator<Item = &'a str> + 'a {
        let mut active = std::collections::BTreeSet::new();
        for text in std::iter::once(self.body.as_str())
            .chain(addons.iter().map(|addon| addon.body.as_str()))
        {
            active.extend(placeholders_in(text));
        }
        self.placeholders
            .iter()
            .filter(move |placeholder| {
                placeholder
                    .default
                    .as_deref()
                    .is_none_or(|default| default.trim().is_empty())
                    && active.contains(&placeholder.name)
            })
            .map(|placeholder| placeholder.name.as_str())
    }

    /// Every prompt that names `id` in its `**Depends on:**`.
    pub fn blocks<'a>(&'a self, library: &'a Library) -> impl Iterator<Item = &'a Prompt> {
        library
            .prompts
            .iter()
            .filter(move |other| other.depends_on.contains(&self.id) && other.is_open())
    }

    /// Existing files this prompt claims.
    pub fn existing_paths(&self) -> impl Iterator<Item = &str> {
        self.touches
            .iter()
            .filter(|touch| touch.claims_existing_file())
            .map(Touch::path)
    }
}

/// The whole library: the shared protocol, the roadmap, and its complaints.
#[derive(Debug)]
pub struct Library {
    /// The file it came from, for every message it prints.
    pub path: PathBuf,
    /// The resolved file that `set-status` rewrites when the display path is root-relative.
    pub source_path: PathBuf,
    /// The text it was parsed from, so the tag can name exactly this version.
    pub source: String,
    /// Prepended to every rendered prompt.
    pub shared_protocol: String,
    /// Every prompt, in library order.
    pub prompts: Vec<Prompt>,
    /// Everything wrong with the library, in the order it was found.
    pub diagnostics: Vec<Diagnostic>,
}

impl Library {
    /// Infallible: a malformed field becomes a [`Diagnostic`] on the prompt that still parsed, so one typo does not hide the next.
    pub fn parse(path: &Path, text: &str) -> Self {
        let lines: Vec<&str> = text.lines().collect();
        let mut diagnostics = Vec::new();
        let mut shared_protocol = String::new();
        let mut shared_line = None;
        let mut prompts: Vec<Prompt> = Vec::new();

        let mut index = 0;
        while index < lines.len() {
            let Some(heading) = heading_body(lines[index]) else {
                index += 1;
                continue;
            };
            let line = index + 1;
            let end = next_heading(&lines, index + 1);
            let section = &lines[index + 1..end];

            if is_shared_protocol(heading) {
                if shared_line.is_none() {
                    shared_protocol =
                        single_fenced_block(section, line, "shared protocol", &mut diagnostics);
                    shared_line = Some(line);
                } else {
                    diagnostics.push(Diagnostic::error(
                        line,
                        "the shared protocol is declared twice; keep one so the order of what is prepended is unambiguous",
                    ));
                }
            } else if let Some((id, title)) = prompt_id(heading) {
                if let Some(previous) = prompts.iter().find(|prompt| prompt.id == id) {
                    diagnostics.push(Diagnostic::error(
                        line,
                        format!(
                            "P{id} is declared twice (also at line {}); ids are how other prompts \
                             refer to each other, so they must be unique",
                            previous.line
                        ),
                    ));
                }
                prompts.push(parse_prompt(id, title, line, section, &mut diagnostics));
            } else if looks_like_a_prompt(heading) {
                diagnostics.push(Diagnostic::warning(
                    line,
                    format!(
                        "`## {heading}` was not read. A prompt heading is `## P<n> · <title>` — \
                         `## Prompt 3` and `## P three` are accepted by other prompt libraries \
                         and mean nothing here"
                    ),
                ));
            }
            index = end;
        }

        if shared_protocol.is_empty() && shared_line.is_none() {
            diagnostics.push(Diagnostic::error(
                0,
                "no `## Shared protocol` section; every rendered prompt starts with it",
            ));
        }
        if prompts.is_empty() {
            diagnostics.push(Diagnostic::error(0, "no prompts found"));
        }
        if let Some(protocol_line) = placeholders_in(&shared_protocol).first() {
            diagnostics.push(Diagnostic::warning(
                shared_line.unwrap_or(0),
                format!(
                    "the shared protocol holds a placeholder `{{{protocol_line}}}`, and it is \
                     prepended verbatim to every prompt, so no `--set` can reliably reach it"
                ),
            ));
        }

        let mut library = Self {
            path: path.to_path_buf(),
            source_path: path.to_path_buf(),
            source: text.to_owned(),
            shared_protocol,
            prompts,
            diagnostics,
        };
        let whole_library = library.check_references();
        library.diagnostics.extend(whole_library);
        library
    }

    /// The prompt with this id.
    pub fn prompt(&self, id: u32) -> Option<&Prompt> {
        self.prompts.iter().find(|prompt| prompt.id == id)
    }

    /// Errors, in library order.
    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Error)
    }

    /// Whether anything blocks rendering.
    pub fn has_errors(&self) -> bool {
        self.errors().next().is_some()
    }

    /// A tag naming the exact library text, for the provenance footer.
    pub fn tag(&self) -> String {
        crate::library_tag(&self.source)
    }

    /// Whole-library checks — dangling deps and cycles — returning findings because the library is still being built.
    fn check_references(&self) -> Vec<Diagnostic> {
        let mut findings = Vec::new();
        let ids: Vec<u32> = self.prompts.iter().map(|prompt| prompt.id).collect();
        for prompt in &self.prompts {
            for dependency in &prompt.depends_on {
                if !ids.contains(dependency) {
                    findings.push(Diagnostic::error(
                        prompt.line,
                        format!(
                            "**Depends on:** names P{dependency}, which is not in this library; \
                             a dependency on nothing is a slice that never becomes ready"
                        ),
                    ));
                }
                if *dependency == prompt.id {
                    findings.push(Diagnostic::error(
                        prompt.line,
                        format!(
                            "P{} depends on itself, so it can never become ready",
                            prompt.id
                        ),
                    ));
                }
            }
        }

        // A cycle leaves every prompt in it permanently unready; name the whole cycle, not just the closing node, so the edit is findable.
        let mut path = Vec::new();
        let mut done = vec![false; self.prompts.len()];
        let cycle =
            (0..self.prompts.len()).find_map(|start| self.find_cycle(start, &mut path, &mut done));
        if let Some(cycle) = cycle {
            let mut names: Vec<String> = cycle
                .iter()
                .map(|&index| format!("P{}", self.prompts[index].id))
                .collect();
            names.push(names[0].clone());
            findings.push(Diagnostic::error(
                self.prompts[cycle[0]].line,
                format!(
                    "the dependency graph has a cycle ({}), so none of these ever becomes ready",
                    names.join(" -> ")
                ),
            ));
        }
        findings
    }

    /// DFS carrying the path so a cycle reports as a path; `done` keeps a dependency diamond from going exponential.
    fn find_cycle(
        &self,
        at: usize,
        path: &mut Vec<usize>,
        done: &mut [bool],
    ) -> Option<Vec<usize>> {
        if done[at] {
            return None;
        }
        if let Some(start) = path.iter().position(|&node| node == at) {
            return Some(path[start..].to_vec());
        }
        path.push(at);
        for dependency in &self.prompts[at].depends_on {
            let Some(next) = self
                .prompts
                .iter()
                .position(|prompt| prompt.id == *dependency)
            else {
                continue;
            };
            if let Some(found) = self.find_cycle(next, path, done) {
                return Some(found);
            }
        }
        path.pop();
        done[at] = true;
        None
    }
}

/// One `## ` heading's text, without the marker.
fn heading_body(line: &str) -> Option<&str> {
    line.strip_prefix("## ").map(str::trim_end)
}

/// Index of the next `## ` heading at or after `from`, or the line count. A fence's body is
/// prose, so a `## ` line inside one is not a section boundary.
fn next_heading(lines: &[&str], from: usize) -> usize {
    let mut fence: Option<(char, usize)> = None;
    for (index, line) in lines.iter().enumerate().skip(from) {
        if let Some((marker, width)) = fence {
            if closes_fence(line, marker, width) {
                fence = None;
            }
            continue;
        }
        if let Some((marker, width)) = opens_fence(line) {
            fence = Some((marker, width));
            continue;
        }
        if heading_body(line).is_some() {
            return index;
        }
    }
    lines.len()
}

/// Up to three leading spaces are indentation; four make the line code, not a fence.
fn fence_body(line: &str) -> Option<&str> {
    let body = line.trim_start_matches(' ');
    (line.len() - body.len() <= 3).then_some(body)
}

/// A fence opening (` ``` ` or `~~~`, at least three) with its marker and width.
pub fn opens_fence(line: &str) -> Option<(char, usize)> {
    let body = fence_body(line)?;
    let marker = body.chars().next()?;
    if marker != '`' && marker != '~' {
        return None;
    }
    let width = body.chars().take_while(|ch| *ch == marker).count();
    if width < 3 || (marker == '`' && body[width..].contains('`')) {
        return None;
    }
    Some((marker, width))
}

/// A closing fence: the same marker at the same width, with only spaces or tabs after it.
pub fn closes_fence(line: &str, marker: char, width: usize) -> bool {
    let Some(body) = fence_body(line) else {
        return false;
    };
    let run = body.chars().take_while(|ch| *ch == marker).count();
    run >= width && body[run..].chars().all(|ch| ch == ' ' || ch == '\t')
}

/// Case-insensitive: the one field name with no id to attach is the one people capitalise.
fn is_shared_protocol(heading: &str) -> bool {
    heading.trim().eq_ignore_ascii_case("shared protocol")
}

/// `(id, title)` from `P<n> · <title>`; the separator is permissive, the id is not: `P two` is a prompt nothing can refer to.
fn prompt_id(heading: &str) -> Option<(u32, &str)> {
    let rest = heading
        .strip_prefix('P')
        .or_else(|| heading.strip_prefix('p'))?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    let title = rest[digits.len()..].trim_start_matches([' ', '\t', '.', ':', '·', '-', '–', '—']);
    Some((digits.parse().ok()?, title.trim()))
}

/// Warning-only, so it can be generous: a spurious warning costs less than a missed prompt.
fn looks_like_a_prompt(heading: &str) -> bool {
    let lower = heading.trim().to_ascii_lowercase();
    lower.starts_with('p') || lower.contains("prompt")
}

/// The one fenced block in a section, with a diagnostic for every way there might not be exactly one.
fn single_fenced_block(
    section: &[&str],
    line: usize,
    what: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> String {
    let mut open = None;
    let mut closed = None;
    let mut fence: Option<(char, usize)> = None;
    for (offset, section_line) in section.iter().enumerate() {
        if let Some((marker, width)) = fence {
            if closes_fence(section_line, marker, width) {
                closed = Some(offset);
                fence = None;
            }
            continue;
        }
        if let Some((marker, width)) = opens_fence(section_line) {
            if open.is_some() {
                diagnostics.push(Diagnostic::error(
                    line + offset + 1,
                    format!(
                        "a second fenced block in the {what} section; exactly one is read, and \
                         which one is not a question this tool answers"
                    ),
                ));
                return String::new();
            }
            open = Some(offset);
            fence = Some((marker, width));
        }
    }
    match (open, closed) {
        (None, _) => {
            diagnostics.push(Diagnostic::error(
                line,
                format!("the {what} section has no fenced block"),
            ));
            String::new()
        }
        (Some(start), None) => {
            diagnostics.push(Diagnostic::error(
                line + start + 1,
                format!("the fenced block in the {what} section is never closed"),
            ));
            String::new()
        }
        (Some(start), Some(end)) => dedent(&section[start + 1..end]),
    }
}

/// True for a fence delimiter and for every line inside it, so callers can skip both.
fn inside_fence(fence: &mut Option<(char, usize)>, line: &str) -> bool {
    if let Some((marker, width)) = *fence {
        if closes_fence(line, marker, width) {
            *fence = None;
        }
        true
    } else if let Some((marker, width)) = opens_fence(line) {
        *fence = Some((marker, width));
        true
    } else {
        false
    }
}

/// Strip common indentation and trailing blanks, so a prompt is not pasted with four spaces per line.
fn dedent(lines: &[&str]) -> String {
    let indent = |line: &str| line.len() - line.trim_start_matches([' ', '\t']).len();
    let common = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| indent(line))
        .min()
        .unwrap_or(0);
    let mut out: Vec<String> = lines
        .iter()
        .map(|line| {
            let trimmed = if indent(line) >= common {
                &line[common..]
            } else {
                line.trim_start()
            };
            trimmed.trim_end().to_owned()
        })
        .collect();
    while out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out.join("\n")
}

/// `**Key:** value`; only the first `:**` ends the key, so a value containing one survives.
fn field(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("**")?;
    let end = rest.find(":**")?;
    Some((&rest[..end], rest[end + 3..].trim()))
}

/// `**Add-on — title:** body`, accepting any dash the two replaced libraries used.
fn addon_line(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix("**Add-on")?;
    let rest = rest.trim_start();
    let rest = rest
        .strip_prefix(['—', '–', '-', ':'])
        .or_else(|| rest.strip_prefix(' '))?;
    let rest = rest.trim_start();
    let end = rest.find(":**")?;
    let title = rest[..end].trim();
    let body = rest[end + 3..].trim();
    if title.is_empty() || body.is_empty() {
        return None;
    }
    Some((title.to_owned(), body.to_owned()))
}

/// ASCII alphanumerics and `-` only; an unusable slug is reported by `check`, never silently mangled.
pub fn slugify(title: &str) -> String {
    let mut slug = String::with_capacity(title.len());
    let mut pending_dash = false;
    for character in title.chars() {
        if character.is_ascii_alphanumeric() {
            if pending_dash && !slug.is_empty() {
                slug.push('-');
            }
            pending_dash = false;
            slug.push(character.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
    }
    slug
}

/// Placeholder names in `text`, in first-appearance order.
fn placeholders_in(text: &str) -> Vec<String> {
    scanned_placeholders(text)
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// Word characters only, so `{}` and `{a b}` are prose; shared with [`crate::render`] so the two cannot disagree.
pub fn is_placeholder_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// The value written after the `=` in a placeholder body, if any.
fn placeholder_default(body: &str) -> Option<String> {
    let (name, default) = body.split_once('=')?;
    debug_assert!(is_placeholder_name(name.trim()));
    Some(default.to_owned())
}

/// Parse one `## P<n>` section.
#[allow(
    clippy::too_many_lines,
    reason = "one arm per metadata field; the dispatcher is where each field's grammar lives"
)]
fn parse_prompt(
    id: u32,
    title: &str,
    line: usize,
    section: &[&str],
    diagnostics: &mut Vec<Diagnostic>,
) -> Prompt {
    let mut prompt = Prompt {
        id,
        title: title.to_owned(),
        when_to_use: String::new(),
        status: Status::Todo,
        leverage: 1,
        effort: Effort::Small,
        gates: Vec::new(),
        depends_on: Vec::new(),
        touches: Vec::new(),
        random_weight: 1,
        targets: Targets::None,
        protocol: String::new(),
        body: String::new(),
        addons: Vec::new(),
        placeholders: Vec::new(),
        line,
    };

    if title.is_empty() {
        diagnostics.push(Diagnostic::error(
            line,
            format!("P{id} has no title; the heading is `## P<n> · <title>`"),
        ));
    }

    let mut fence = None;
    for (offset, section_line) in section.iter().enumerate() {
        let field_line = line + offset + 1;
        if inside_fence(&mut fence, section_line) {
            continue;
        }
        if let Some((addon_title, body)) = addon_line(section_line) {
            let slug = slugify(&addon_title);
            if slug.is_empty() {
                diagnostics.push(Diagnostic::error(
                    field_line,
                    format!(
                        "P{id}: the add-on `{addon_title}` has no typeable name. Rename it in \
                         ASCII words, or check will report it every run"
                    ),
                ));
            } else if prompt.addons.iter().any(|addon| addon.slug == slug) {
                diagnostics.push(Diagnostic::error(
                    field_line,
                    format!("P{id}: two add-ons are both called `{slug}`; slugs have to differ"),
                ));
            } else {
                prompt.addons.push(Addon {
                    title: addon_title,
                    slug,
                    body,
                });
            }
            continue;
        }
        let Some((key, value)) = field(section_line) else {
            continue;
        };
        match key {
            "When to use" => value.clone_into(&mut prompt.when_to_use),
            "Status" => match Status::parse(value) {
                Some(status) => prompt.status = status,
                None => diagnostics.push(Diagnostic::error(
                    field_line,
                    format!(
                        "P{id}: **Status:** `{value}` is not one of {}",
                        Status::NAMES.join(", ")
                    ),
                )),
            },
            "Leverage" => match value.parse::<u8>() {
                Ok(leverage @ 1..=5) => prompt.leverage = leverage,
                _ => diagnostics.push(Diagnostic::error(
                    field_line,
                    format!("P{id}: **Leverage:** must be a number from 1 to 5, not `{value}`"),
                )),
            },
            "Effort" => match Effort::parse(value) {
                Some(effort) => prompt.effort = effort,
                None => diagnostics.push(Diagnostic::error(
                    field_line,
                    format!(
                        "P{id}: **Effort:** `{value}` is not one of {}",
                        Effort::NAMES.join(", ")
                    ),
                )),
            },
            "Gates" => {
                prompt.gates = value
                    .split(';')
                    .map(str::trim)
                    .filter(|gate| !gate.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            "Depends on" => {
                for item in value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                {
                    match item.trim_start_matches(['P', 'p']).parse::<u32>() {
                        Ok(dependency) => prompt.depends_on.push(dependency),
                        Err(_) => diagnostics.push(Diagnostic::error(
                            field_line,
                            format!(
                                "P{id}: **Depends on:** `{item}` is not a prompt id; \
                                 write it as P<n> or as the bare number"
                            ),
                        )),
                    }
                }
            }
            "Touches" => {
                prompt.touches = value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(|item| match item.strip_prefix('+') {
                        Some(path) => Touch::Created(path.trim().to_owned()),
                        None => Touch::Existing(item.to_owned()),
                    })
                    .collect();
            }
            "Random weight" => match value.parse::<u32>() {
                Ok(weight @ 0..=9) => prompt.random_weight = weight,
                _ => diagnostics.push(Diagnostic::error(
                    field_line,
                    format!(
                        "P{id}: **Random weight:** must be a number from 0 to 9, not `{value}`"
                    ),
                )),
            },
            "Prompt protocol" => value.clone_into(&mut prompt.protocol),
            "Targets" => match Targets::parse(value) {
                Some(targets) => prompt.targets = targets,
                None => diagnostics.push(Diagnostic::error(
                    field_line,
                    format!(
                        "P{id}: **Targets:** `{value}` is not one of {}",
                        Targets::NAMES.join(", ")
                    ),
                )),
            },
            other => diagnostics.push(Diagnostic::warning(
                field_line,
                format!(
                    "P{id}: `**{other}:**` is not a field this tool reads, so it has no effect; \
                     the fields are When to use, Status, Leverage, Effort, Gates, Depends on, \
                     Touches, Random weight, Targets and Prompt protocol"
                ),
            )),
        }
    }

    prompt.body = single_fenced_block(section, line, &format!("P{id}"), diagnostics);

    for (name, why) in REQUIRED_FIELDS {
        if !section_has_field(section, name) {
            diagnostics.push(Diagnostic::error(
                line,
                format!("P{id} has no `**{name}:**` line: {why}"),
            ));
        }
    }
    if prompt.when_to_use.is_empty() {
        diagnostics.push(Diagnostic::error(
            line,
            format!(
                "P{id} has no **When to use:** text: {}",
                REQUIRED_FIELDS[0].1
            ),
        ));
    }
    if prompt.gates.is_empty() {
        diagnostics.push(Diagnostic::error(
            line,
            format!(
                "P{id} has no **Gates:**; a slice with no check is a slice nobody can tell is \
                 finished, and this repository does not claim things nothing checks"
            ),
        ));
    }

    collect_placeholders(&mut prompt, diagnostics);
    prompt
}

/// Fields whose absence blocks the slice, kept beside the parser so a new one is one line.
const REQUIRED_FIELDS: &[(&str, &str)] = &[
    (
        "When to use",
        "a prompt nobody can place is a prompt nobody starts",
    ),
    (
        "Status",
        "the advisor picks from statuses, so an unstated prompt is invisible to it",
    ),
    (
        "Leverage",
        "the advisor ranks on it, so an unstated prompt is ranked last by accident",
    ),
    ("Effort", "the advisor breaks ties with it"),
    (
        "Targets",
        "a matrix prompt without a target class is never expanded for a row",
    ),
];

/// Whether a field appears at all, as opposed to appearing empty.
fn section_has_field(section: &[&str], key: &str) -> bool {
    let mut fence = None;
    for line in section {
        if inside_fence(&mut fence, line) {
            continue;
        }
        if let Some((found, _)) = field(line) {
            if found == key {
                return true;
            }
        }
    }
    false
}

/// Collect the placeholders a prompt needs, from its body and its add-ons.
fn collect_placeholders(prompt: &mut Prompt, diagnostics: &mut Vec<Diagnostic>) {
    let id = prompt.id;
    for source in std::iter::once(prompt.body.clone())
        .chain(prompt.addons.iter().map(|addon| addon.body.clone()))
    {
        for (name, default) in scanned_placeholders(&source) {
            match prompt
                .placeholders
                .iter_mut()
                .find(|slot| slot.name == name)
            {
                Some(slot) => {
                    if slot.default != default {
                        let detail = match (&slot.default, &default) {
                            (Some(first), Some(second)) => format!(
                                "P{id}: the placeholder {{ {name} }} has two defaults, `{first}` and \
                                 `{second}`; one value cannot be both"
                            ),
                            _ => format!(
                                "P{id}: the placeholder {{ {name} }} appears both with and without a \
                                 default; one is always required or always defaulted, because a \
                                 value that is sometimes required and sometimes not is a value \
                                 nobody knows to supply"
                            ),
                        };
                        diagnostics.push(Diagnostic::error(prompt.line, detail));
                    }
                }
                None => prompt.placeholders.push(Placeholder { name, default }),
            }
        }
    }
}

/// One scanner shared with [`placeholders_in`], so two callers cannot answer differently.
fn scanned_placeholders(text: &str) -> Vec<(String, Option<String>)> {
    let mut found = Vec::new();
    let mut index = 0;
    while index < text.len() {
        let Some(character) = text[index..].chars().next() else {
            break;
        };
        if character != '{' {
            index += character.len_utf8();
            continue;
        }
        let after = index + 1;
        if text[after..].starts_with('{') {
            index = after + 1;
            continue;
        }
        let Some(close) = text[after..].find('}').map(|offset| after + offset) else {
            break;
        };
        let body = &text[after..close];
        let name = body.split('=').next().unwrap_or("").trim();
        if is_placeholder_name(name) {
            found.push((name.to_owned(), placeholder_default(body.trim())));
            index = close + 1;
        } else {
            index = after;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIBRARY: &str = "\
## Shared protocol

```text
stand up
```

## P1 · First

**When to use:** always
**Status:** done
**Leverage:** 5
**Effort:** small
**Targets:** none
**Gates:** `cargo test`
**Touches:** crates/ferrox-core/src/lib.rs
**Random weight:** 0

```text
do the first thing with {len=40}
```

**Add-on — Local first:** author here, prove in CI

## P2 · Second

**When to use:** after the first
**Status:** todo
**Leverage:** 3
**Effort:** large
**Targets:** none
**Gates:** `cargo clippy`; CI: `ci.yml`
**Depends on:** P1
**Touches:** +crates/ferrox-prompt/src/new.rs

```text
do the second thing with {scope}
```

**Add-on — miri-limits:** name what it cannot interpret
";

    fn load(text: &str) -> Library {
        Library::parse(Path::new("prompts.md"), text)
    }

    #[test]
    fn a_prompt_without_targets_is_an_error() {
        let library = load(&LIBRARY.replace("**Targets:** none\n", ""));
        let named = library
            .errors()
            .any(|error| error.message.contains("**Targets:**"));
        assert!(
            named,
            "the missing target class is named: {:?}",
            library.diagnostics
        );
    }

    #[test]
    fn a_library_parses_into_prompts() {
        let library = load(LIBRARY);
        assert!(
            !library.has_errors(),
            "unexpected: {:?}",
            library.diagnostics
        );
        assert_eq!(library.shared_protocol, "stand up");
        assert_eq!(library.prompts.len(), 2);
        let first = library.prompt(1).unwrap();
        assert_eq!(first.title, "First");
        assert_eq!(first.when_to_use, "always");
        assert_eq!(first.status, Status::Done);
        assert_eq!(first.leverage, 5);
        assert_eq!(first.effort, Effort::Small);
        assert_eq!(first.gates, vec!["`cargo test`"]);
        assert_eq!(first.random_weight, 0);
        assert_eq!(first.body, "do the first thing with {len=40}");
        assert_eq!(first.addons.len(), 1);
        assert_eq!(first.addons[0].slug, "local-first");
        assert_eq!(first.placeholders.len(), 1);
        assert_eq!(first.placeholders[0].default.as_deref(), Some("40"));
        assert_eq!(first.touches.len(), 1);
        assert!(first.touches[0].claims_existing_file());
    }

    #[test]
    fn a_prompt_with_no_default_has_a_required_input() {
        let library = load(LIBRARY);
        let second = library.prompt(2).unwrap();
        assert_eq!(second.required_inputs().collect::<Vec<_>>(), vec!["scope"]);
        assert_eq!(second.depends_on, vec![1]);
        assert_eq!(second.effort, Effort::Large);
        assert_eq!(second.gates.len(), 2);
        assert!(!second.touches[0].claims_existing_file());
    }

    #[test]
    fn a_typo_in_a_field_is_a_warning_not_silence() {
        let library = load(&LIBRARY.replace("**Leverage:** 5", "**Levrage:** 5"));
        let typo = library
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.message.contains("Levrage"))
            .expect("a misspelled field must be reported");
        assert_eq!(typo.severity, Severity::Warning);
        assert!(typo.line > 0);
    }

    #[test]
    fn a_second_fenced_block_is_an_error() {
        let text = LIBRARY.replace(
            "**Add-on — Local first:** author here, prove in CI",
            "```text\na second block\n```\n",
        );
        let library = load(&text);
        assert!(
            library
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("second fenced block")),
            "a section with two blocks must not be guessed at: {:?}",
            library.diagnostics
        );
    }

    #[test]
    fn an_unclosed_block_is_an_error() {
        let library = load("## Shared protocol\n\n```text\nunterminated\n");
        assert!(library.has_errors());
    }

    #[test]
    fn a_dependency_on_a_prompt_that_does_not_exist_is_an_error() {
        let library = load(&LIBRARY.replace("**Depends on:** P1", "**Depends on:** P9"));
        assert!(library.errors().any(|error| error.message.contains("P9")));
    }

    #[test]
    fn a_cycle_is_reported_with_the_prompts_in_it() {
        let text = "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** none
**Gates:** `cargo test`
**Depends on:** P2

```text
b
```

## P2 · Two

**When to use:** second
**Status:** todo
**Leverage:** 1
**Effort:** small
**Targets:** none
**Gates:** `cargo test`
**Depends on:** P1

```text
b
```
";
        let library = load(text);
        let cycle = library
            .errors()
            .find(|error| error.message.contains("cycle"))
            .unwrap_or_else(|| {
                panic!(
                    "a cycle must be named, not left to hang: {:?}",
                    library.diagnostics
                )
            });
        assert!(cycle.message.contains("P1"), "{}", cycle.message);
        assert!(cycle.message.contains("P2"), "{}", cycle.message);
    }

    #[test]
    fn a_prompt_depending_on_itself_is_named() {
        let library = load(&LIBRARY.replace("**Depends on:** P1", "**Depends on:** P2"));
        let self_dependency = library
            .errors()
            .find(|error| error.message.contains("depends on itself"))
            .unwrap_or_else(|| {
                panic!(
                    "expected a self-dependency error: {:?}",
                    library.diagnostics
                )
            });
        assert!(self_dependency.message.contains('P'));
    }

    #[test]
    fn a_heading_from_another_library_is_a_warning() {
        let library = load(&LIBRARY.replace("## P2 · Second", "## Prompt 2: Second"));
        let warning = library
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.severity == Severity::Warning)
            .unwrap_or_else(|| panic!("expected a warning, got {:?}", library.diagnostics));
        assert!(warning.message.contains("## P<n>"), "{}", warning.message);
    }

    #[test]
    fn an_out_of_range_leverage_is_an_error() {
        let library = load(&LIBRARY.replace("**Leverage:** 5", "**Leverage:** 9"));
        assert!(library
            .errors()
            .any(|error| error.message.contains("1 to 5")));
        let word = load(&LIBRARY.replace("**Leverage:** 5", "**Leverage:** high"));
        assert!(word.errors().any(|error| error.message.contains("1 to 5")));
    }

    #[test]
    fn a_prompt_with_no_gates_is_an_error() {
        let library = load(&LIBRARY.replace("**Gates:** `cargo test`\n", ""));
        assert!(library
            .errors()
            .any(|error| error.message.contains("**Gates:**")));
    }

    #[test]
    fn slugs_are_lowercase_and_dashed() {
        assert_eq!(slugify("Local first"), "local-first");
        assert_eq!(slugify("miri  limits!"), "miri-limits");
        assert_eq!(slugify("Isa's ISA matrix"), "isa-s-isa-matrix");
        assert_eq!(slugify("---"), "");
    }

    #[test]
    fn a_lone_brace_does_not_swallow_a_later_placeholder() {
        assert_eq!(
            scanned_placeholders("a { b {name}"),
            vec![("name".to_owned(), None)]
        );
    }

    #[test]
    fn a_whitespace_only_default_is_a_required_input() {
        let library = load(&LIBRARY.replace("{len=40}", "{len= }"));
        let first = library.prompt(1).unwrap();
        assert_eq!(first.placeholders[0].default.as_deref(), Some(""));
        assert_eq!(first.required_inputs().collect::<Vec<_>>(), vec!["len"]);
    }

    #[test]
    fn placeholders_may_have_defaults_that_contain_equals() {
        let library = load(&LIBRARY.replace("{len=40}", "{cmd=cargo test --all}"));
        let first = library.prompt(1).unwrap();
        assert_eq!(
            first.placeholders[0].default.as_deref(),
            Some("cargo test --all")
        );
    }

    #[test]
    fn an_indented_fence_is_code_and_does_not_hide_a_heading() {
        let lines = [
            "## P1 · First",
            "    ```",
            "    ## P2 · Second",
            "    ```",
            "## P2 · Second",
        ];
        assert_eq!(next_heading(&lines, 1), 4);
    }

    #[test]
    fn only_a_bare_identical_marker_closes_a_fence() {
        assert_eq!(opens_fence("```"), Some(('`', 3)));
        assert!(!closes_fence("~~~text", '~', 3));
        assert!(!closes_fence("````text", '`', 3));
        assert!(closes_fence("~~~", '~', 3));
        assert!(closes_fence("````  ", '`', 3));
    }

    #[test]
    fn fenced_example_metadata_cannot_change_the_real_prompt() {
        let text = LIBRARY.replace(
            "do the second thing with {scope}\n```",
            "do the second thing with {scope}\n```\n\n~~~text\n## P9 · Example\n**Status:** done\n~~~",
        );
        let library = load(&text);
        assert_eq!(library.prompt(2).unwrap().status, Status::Todo);
        assert!(library.prompt(9).is_none());
    }

    #[test]
    fn two_different_defaults_are_an_error() {
        let library = load(&LIBRARY.replace(
            "do the second thing with {scope}",
            "do {scope=one} and {scope=two}",
        ));
        assert!(library
            .errors()
            .any(|error| error.message.contains("two defaults")));
    }

    #[test]
    fn the_live_library_has_no_errors() {
        let text = include_str!("../prompts.md");
        let library = Library::parse(Path::new("prompts.md"), text);
        assert!(
            !library.has_errors(),
            "prompts.md does not parse: {:#?}",
            library.diagnostics
        );
    }
}
