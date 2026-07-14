//! Turns a list of processes into plain, aligned text for the terminal.
//!
//! Hand-rolled on purpose: computing a couple of column widths with `format!`
//! is a few lines, so pulling in a table crate would be more dependency than the
//! job needs (YAGNI). If the output ever grows real columns and wrapping, revisit.
//!
//! The renderer returns a `String` instead of printing directly, which keeps it
//! a pure function -- easy to unit-test without capturing stdout.

use hightower_core::process::ProcessInfo;

/// Renders the running processes as an aligned three-column table
/// (PID / NAME / PATH) and returns it as a single string ending in a newline.
///
/// A process whose path the OS withheld shows `(restricted)` in the PATH column
/// rather than being hidden -- it is still something the user should see.
pub fn render_process_table(processes: &[ProcessInfo]) -> String {
    const PID_HEADER: &str = "PID";
    const NAME_HEADER: &str = "NAME";
    const PATH_HEADER: &str = "PATH";

    // Build the display strings once (pid as text, path or a "(restricted)"
    // placeholder), so width calculation and rendering see the same values.
    let mut rows: Vec<(String, String, String)> = Vec::new();
    for process in processes {
        let path = match &process.executable_path {
            Some(path) => path.display().to_string(),
            None => "(restricted)".to_string(),
        };
        rows.push((process.pid.to_string(), process.name.clone(), path));
    }

    // Each column is as wide as the widest of its header and its cells. PATH is
    // last, so it never needs padding.
    let mut pid_width = PID_HEADER.len();
    let mut name_width = NAME_HEADER.len();
    for (pid, name, _path) in &rows {
        pid_width = pid_width.max(pid.len());
        name_width = name_width.max(name.len());
    }

    let mut output = String::new();
    // PID is a number, so it reads better right-aligned; text is left-aligned.
    output.push_str(&format!(
        "{PID_HEADER:>pid_width$}  {NAME_HEADER:<name_width$}  {PATH_HEADER}\n"
    ));
    for (pid, name, path) in &rows {
        output.push_str(&format!("{pid:>pid_width$}  {name:<name_width$}  {path}\n"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use hightower_core::process::SignatureStatus;
    use std::path::PathBuf;

    fn process(pid: u32, name: &str, path: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.to_string(),
            executable_path: path.map(PathBuf::from),
            restricted: path.is_none(),
            signature: SignatureStatus::Unchecked,
        }
    }

    #[test]
    fn renders_header_and_rows() {
        let processes = [
            process(4, "System", None),
            process(1234, "explorer.exe", Some(r"C:\Windows\explorer.exe")),
        ];
        let table = render_process_table(&processes);

        assert!(table.contains("PID"));
        assert!(table.contains("NAME"));
        assert!(table.contains("PATH"));
        assert!(table.contains("explorer.exe"));
        assert!(table.contains(r"C:\Windows\explorer.exe"));
        // The process the OS withheld is shown, not dropped.
        assert!(table.contains("(restricted)"));
    }

    #[test]
    fn columns_are_aligned_to_the_widest_cell() {
        let processes = [
            process(1, "a", Some("p1")),
            process(2, "longer-name.exe", Some("p2")),
        ];
        let table = render_process_table(&processes);
        let lines: Vec<&str> = table.lines().collect();

        // A short and a long name in the NAME column must still line the PATH
        // column up at the same byte offset on both rows.
        let short_row = lines.iter().find(|line| line.contains("p1")).unwrap();
        let long_row = lines.iter().find(|line| line.contains("p2")).unwrap();
        assert_eq!(short_row.find("p1"), long_row.find("p2"));
    }
}
