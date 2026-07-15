//! Turns classified processes into a table for the terminal.
//!
//! Two renderers behind one entry point, chosen by [`RenderStyle::color`]:
//!
//! - **plain** (pipes, `NO_COLOR`, `--no-color`): the original hand-rolled,
//!   borderless, monochrome table. Still the cheapest thing that works for a
//!   flat, machine-friendly dump, so it stays hand-rolled.
//! - **rich** (an interactive terminal): a box-drawn table with a coloured RISK
//!   column and a PATH column truncated to the terminal width. This is where
//!   hand-rolling stopped paying off -- colour, per-cell styling, box borders and
//!   width-aware truncation are exactly what `comfy-table` exists for -- so this
//!   path reverts the earlier YAGNI call and uses it.
//!
//! Both renderers are pure functions returning a `String`; the colour/width
//! decision is an argument, never read from the environment here.

use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Table};

use hightower_core::process::{ProcessVerdict, RiskLevel};

use crate::render::{category_label, risk_label, truncate_middle, RenderStyle};

const HEADERS: [&str; 5] = ["RISK", "PID", "NAME", "CATEGORY", "PATH"];

/// Renders the verdicts as a table. Callers sort worst-first beforehand, so the
/// flagged processes appear at the top.
pub fn render_verdict_table(verdicts: &[ProcessVerdict], style: RenderStyle) -> String {
    if style.color {
        render_rich(verdicts, style)
    } else {
        render_plain(verdicts)
    }
}

/// The plain, borderless, monochrome table (no truncation).
fn render_plain(verdicts: &[ProcessVerdict]) -> String {
    let rows: Vec<[String; 5]> = verdicts.iter().map(row_cells).collect();

    // Each column is as wide as the widest of its header and its cells. PATH is
    // last, so it never needs padding.
    let mut widths = HEADERS.map(|header| header.len());
    for cells in &rows {
        for (width, cell) in widths.iter_mut().zip(cells) {
            *width = (*width).max(cell.len());
        }
    }
    let [risk_w, pid_w, name_w, category_w, _path_w] = widths;

    let mut output = String::new();
    let [risk, pid, name, category, path] = HEADERS;
    // PID is a number, so it reads better right-aligned; text is left-aligned.
    output.push_str(&format!(
        "{risk:<risk_w$}  {pid:>pid_w$}  {name:<name_w$}  {category:<category_w$}  {path}\n"
    ));
    for [risk, pid, name, category, path] in &rows {
        output.push_str(&format!(
            "{risk:<risk_w$}  {pid:>pid_w$}  {name:<name_w$}  {category:<category_w$}  {path}\n"
        ));
    }
    output
}

/// The rich, box-drawn, coloured table with a width-truncated PATH column.
fn render_rich(verdicts: &[ProcessVerdict], style: RenderStyle) -> String {
    let path_budget = style.max_width.map(|width| path_budget(verdicts, width));

    let mut table = Table::new();
    table.load_preset(comfy_table::presets::UTF8_FULL);
    // We size the PATH column ourselves (truncating, not wrapping), so comfy-table
    // must not re-flow the content.
    table.set_content_arrangement(ContentArrangement::Disabled);
    table.enforce_styling(); // colour is already gated by the caller (style.color)
    table.set_header(HEADERS);

    for verdict in verdicts {
        let [risk, pid, name, category, mut path] = row_cells(verdict);
        if let Some(budget) = path_budget {
            path = truncate_middle(&path, budget);
        }

        let risk_cell = {
            let cell = Cell::new(risk).fg(risk_color(verdict.risk));
            if verdict.risk == RiskLevel::Suspicious {
                cell.add_attribute(Attribute::Bold)
            } else {
                cell
            }
        };
        table.add_row(vec![
            risk_cell,
            Cell::new(pid).set_alignment(CellAlignment::Right),
            Cell::new(name),
            Cell::new(category),
            Cell::new(path),
        ]);
    }

    table.to_string()
}

/// Builds the five display strings for one verdict, shared by both renderers.
fn row_cells(verdict: &ProcessVerdict) -> [String; 5] {
    let path = match &verdict.process.executable_path {
        Some(path) => path.display().to_string(),
        None => "(restricted)".to_string(),
    };
    [
        risk_label(verdict.risk).to_string(),
        verdict.process.pid.to_string(),
        verdict.process.name.clone(),
        category_label(verdict.category).to_string(),
        path,
    ]
}

/// How many columns the PATH cell may use: the terminal width minus the other
/// four columns (at their natural widths) and comfy-table's border/padding
/// overhead. Clamped to a small minimum so a narrow terminal still shows a stub.
fn path_budget(verdicts: &[ProcessVerdict], terminal_width: usize) -> usize {
    // Widest of header and cells for every column except PATH.
    let mut widths = [
        HEADERS[0].len(),
        HEADERS[1].len(),
        HEADERS[2].len(),
        HEADERS[3].len(),
    ];
    for verdict in verdicts {
        let cells = row_cells(verdict);
        for (width, cell) in widths.iter_mut().zip(cells.iter().take(4)) {
            *width = (*width).max(cell.len());
        }
    }

    // UTF8_FULL overhead for 5 columns: 6 vertical borders + 5x2 padding spaces.
    const BORDER_OVERHEAD: usize = 16;
    let fixed: usize = widths.iter().sum::<usize>() + BORDER_OVERHEAD;
    terminal_width.saturating_sub(fixed).max(12)
}

/// comfy-table colour for a risk level (paired with bold for suspicious).
fn risk_color(risk: RiskLevel) -> Color {
    match risk {
        RiskLevel::Trusted => Color::Green,
        RiskLevel::Review => Color::Yellow,
        RiskLevel::Suspicious => Color::Red,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hightower_core::process::{ProcessCategory, ProcessInfo, SignatureStatus};
    use std::path::PathBuf;

    fn verdict(
        pid: u32,
        name: &str,
        path: Option<&str>,
        category: ProcessCategory,
        risk: RiskLevel,
    ) -> ProcessVerdict {
        ProcessVerdict {
            process: ProcessInfo {
                pid,
                name: name.to_string(),
                executable_path: path.map(PathBuf::from),
                restricted: path.is_none(),
                signature: SignatureStatus::Unchecked,
            },
            category,
            publisher: None,
            risk,
            findings: Vec::new(),
        }
    }

    fn sample() -> Vec<ProcessVerdict> {
        vec![
            verdict(
                4,
                "System",
                None,
                ProcessCategory::Unknown,
                RiskLevel::Review,
            ),
            verdict(
                1234,
                "explorer.exe",
                Some(r"C:\Windows\explorer.exe"),
                ProcessCategory::CoreWindows,
                RiskLevel::Trusted,
            ),
        ]
    }

    #[test]
    fn plain_renders_headers_labels_and_restricted() {
        let table = render_verdict_table(&sample(), RenderStyle::plain());
        for header in HEADERS {
            assert!(table.contains(header), "missing header {header}");
        }
        assert!(table.contains("trusted"));
        assert!(table.contains("review"));
        assert!(table.contains("core-windows"));
        assert!(table.contains("(restricted)"));
        assert!(table.contains(r"C:\Windows\explorer.exe"));
    }

    #[test]
    fn plain_output_has_no_escape_sequences() {
        let table = render_verdict_table(&sample(), RenderStyle::plain());
        assert!(!table.contains('\x1b'), "plain output must be escape-free");
    }

    #[test]
    fn plain_columns_are_aligned() {
        let verdicts = [
            verdict(
                1,
                "a",
                Some("p1"),
                ProcessCategory::Unknown,
                RiskLevel::Trusted,
            ),
            verdict(
                2,
                "much-longer-name.exe",
                Some("p2"),
                ProcessCategory::Unknown,
                RiskLevel::Trusted,
            ),
        ];
        let table = render_verdict_table(&verdicts, RenderStyle::plain());
        let lines: Vec<&str> = table.lines().collect();
        let short_row = lines.iter().find(|line| line.contains("p1")).unwrap();
        let long_row = lines.iter().find(|line| line.contains("p2")).unwrap();
        assert_eq!(short_row.find("p1"), long_row.find("p2"));
    }

    #[test]
    fn rich_output_has_borders_and_colour() {
        let style = RenderStyle {
            color: true,
            max_width: None,
        };
        let table = render_verdict_table(&sample(), style);
        assert!(table.contains('│'), "rich output should be box-drawn");
        assert!(table.contains('\x1b'), "rich output should be coloured");
    }

    #[test]
    fn rich_truncates_a_long_path_to_the_width() {
        let long = r"C:\Program Files\Some Vendor\Very Long Application Name\bin\service.exe";
        let verdicts = [verdict(
            9,
            "service.exe",
            Some(long),
            ProcessCategory::Unknown,
            RiskLevel::Review,
        )];
        let style = RenderStyle {
            color: true,
            max_width: Some(60),
        };
        let table = render_verdict_table(&verdicts, style);
        assert!(
            !table.contains(long),
            "the full long path should be truncated"
        );
        assert!(table.contains('…'));
    }
}
