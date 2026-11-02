//! Compact, token-efficient text renderings for tool results.

use nosy_codec::is_printable;
use nosy_model::FlowSummary;

pub fn size(n: Option<i64>) -> String {
    match n {
        None => "-".into(),
        Some(n) if n < 1024 => format!("{n} B"),
        Some(n) if n < 1024 * 1024 => format!("{:.1} KB", n as f64 / 1024.0),
        Some(n) => format!("{:.2} MB", n as f64 / 1024.0 / 1024.0),
    }
}

pub fn duration(us: Option<i64>) -> String {
    match us {
        None => "-".into(),
        Some(us) if us < 1000 => format!("{us} µs"),
        Some(us) if us < 1_000_000 => format!("{} ms", us / 1000),
        Some(us) => format!("{:.2} s", us as f64 / 1e6),
    }
}

fn mime(ct: Option<&str>) -> String {
    let Some(ct) = ct else { return "-".into() };
    let base = ct.split(';').next().unwrap_or(ct).trim();
    base.rsplit('/').next().unwrap_or(base).to_owned()
}

pub fn url(f: &FlowSummary) -> String {
    let default = if f.scheme == "https" { 443 } else { 80 };
    if f.port == default {
        format!("{}://{}{}", f.scheme, f.host, f.path)
    } else {
        format!("{}://{}:{}{}", f.scheme, f.host, f.port, f.path)
    }
}

/// `#118 GET 200 https://host/path · 1.2 KB · json · 84 ms [note]`
pub fn flow_line(f: &FlowSummary) -> String {
    let status = match (f.status, &f.error) {
        (Some(s), _) => s.to_string(),
        (None, Some(_)) => "ERR".into(),
        (None, None) => "…".into(),
    };
    let mut line = format!(
        "#{} {} {} {} · {} · {} · {}",
        f.id,
        f.method,
        status,
        url(f),
        size(f.resp_size),
        mime(f.content_type.as_deref()),
        duration(f.duration_us)
    );
    if let Some(h) = &f.highlight {
        line.push_str(&format!(" [highlight:{h}]"));
    }
    if let Some(n) = &f.note {
        line.push_str(&format!(" [note: {n}]"));
    }
    if let Some(e) = &f.error {
        line.push_str(&format!(" [error: {e}]"));
    }
    line
}

/// Render a raw HTTP message (head + already-decoded body) for a model.
pub fn message(raw: &[u8], max_body_chars: usize) -> String {
    let (head, body) = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => (&raw[..i], &raw[i + 4..]),
        None => (raw, &raw[raw.len()..]),
    };
    let mut out = String::from_utf8_lossy(head).replace("\r\n", "\n");
    out.push_str("\n\n");
    out.push_str(&body_text(body, max_body_chars));
    out
}

pub fn body_text(body: &[u8], max_chars: usize) -> String {
    if body.is_empty() {
        return "(empty body)".into();
    }
    if !is_printable(body) {
        let preview = &body[..body.len().min(64)];
        return format!(
            "[binary body: {} bytes; first {} bytes as hex: {}]",
            body.len(),
            preview.len(),
            nosy_codec::transform::hex(preview)
        );
    }
    let text = String::from_utf8_lossy(body);
    truncate(&text, max_chars)
}

pub fn truncate(text: &str, max_chars: usize) -> String {
    let total = text.chars().count();
    if total <= max_chars {
        return text.to_owned();
    }
    let cut: String = text.chars().take(max_chars).collect();
    format!(
        "{cut}\n[… truncated: {} more chars; raise max_body_chars to see more]",
        total - max_chars
    )
}
