//! Structured edits to raw HTTP/1.x request text (used by `replay_flow`).

use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct Edits<'a> {
    pub method: Option<&'a str>,
    pub path: Option<&'a str>,
    /// Replace (or add) these headers. Case-insensitive names; duplicates are collapsed.
    pub set_headers: Option<&'a BTreeMap<String, String>>,
    pub remove_headers: Option<&'a [String]>,
    pub body: Option<&'a str>,
}

/// Apply `edits` to `raw` and return CRLF-normalized request text.
/// Content-Length is left to the repeater, which recomputes it.
pub fn apply(raw: &str, edits: &Edits<'_>) -> String {
    let (head, body) = match raw
        .find("\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| raw.find("\n\n").map(|i| (i, 2)))
    {
        Some((i, sep)) => (&raw[..i], &raw[i + sep..]),
        None => (raw.trim_end_matches(['\r', '\n']), ""),
    };
    let mut lines = head.lines().map(|l| l.trim_end_matches('\r'));
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.splitn(3, ' ');
    let (orig_method, orig_path, version) = (
        parts.next().unwrap_or("GET"),
        parts.next().unwrap_or("/"),
        parts.next().unwrap_or("HTTP/1.1"),
    );
    let method = edits.method.unwrap_or(orig_method);
    let path = edits.path.unwrap_or(orig_path);

    let name_of = |l: &str| {
        l.split_once(':')
            .map(|(n, _)| n.trim().to_ascii_lowercase())
    };
    let removed: Vec<String> = edits
        .remove_headers
        .unwrap_or_default()
        .iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    let set: BTreeMap<String, (&str, &str)> = edits
        .set_headers
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), (k.as_str(), v.as_str())))
                .collect()
        })
        .unwrap_or_default();

    let mut out = format!("{} {} {}\r\n", method.to_ascii_uppercase(), path, version);
    let mut written = std::collections::HashSet::new();
    for line in lines {
        let Some(name) = name_of(line) else {
            out.push_str(line);
            out.push_str("\r\n");
            continue;
        };
        if removed.contains(&name) {
            continue;
        }
        if let Some((orig, value)) = set.get(&name) {
            if written.insert(name.clone()) {
                out.push_str(&format!("{orig}: {value}\r\n"));
            }
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    for (name, (orig, value)) in &set {
        if !written.contains(name) {
            out.push_str(&format!("{orig}: {value}\r\n"));
        }
    }
    out.push_str("\r\n");
    out.push_str(edits.body.unwrap_or(body));
    out
}

/// `(host, port)` from the request's Host header, if any.
pub fn host_header(raw: &str) -> Option<(String, Option<u16>)> {
    raw.lines()
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .find_map(|l| {
            let (n, v) = l.split_once(':')?;
            if !n.trim().eq_ignore_ascii_case("host") {
                return None;
            }
            let v = v.trim();
            // [v6]:port, host:port, host
            if let Some(rest) = v.strip_prefix('[') {
                let (h, p) = rest.split_once(']')?;
                return Some((
                    h.to_owned(),
                    p.strip_prefix(':').and_then(|p| p.parse().ok()),
                ));
            }
            Some(match v.rsplit_once(':') {
                Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_owned(), p.parse().ok()),
                _ => (v.to_owned(), None),
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = "POST /a?x=1 HTTP/1.1\r\nHost: ex.com\r\nCookie: a=1\r\nX-Dup: 1\r\nx-dup: 2\r\nContent-Length: 3\r\n\r\nabc";

    #[test]
    fn edits_line_headers_and_body() {
        let set = BTreeMap::from([
            ("X-Dup".to_owned(), "9".to_owned()),
            ("X-New".to_owned(), "n".to_owned()),
        ]);
        let remove = vec!["cookie".to_owned()];
        let out = apply(
            RAW,
            &Edits {
                method: Some("put"),
                path: Some("/b"),
                set_headers: Some(&set),
                remove_headers: Some(&remove),
                body: Some("{}"),
            },
        );
        assert_eq!(
            out,
            "PUT /b HTTP/1.1\r\nHost: ex.com\r\nX-Dup: 9\r\nContent-Length: 3\r\nX-New: n\r\n\r\n{}"
        );
    }

    #[test]
    fn path_only_keeps_version() {
        let out = apply(
            RAW,
            &Edits {
                path: Some("/x"),
                ..Default::default()
            },
        );
        assert!(out.starts_with("POST /x HTTP/1.1\r\n"), "{out}");
    }

    #[test]
    fn no_edits_normalizes_only() {
        let out = apply("GET / HTTP/1.1\nHost: a\n\n", &Edits::default());
        assert_eq!(out, "GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    }

    #[test]
    fn parses_host_header() {
        assert_eq!(host_header(RAW), Some(("ex.com".into(), None)));
        assert_eq!(
            host_header("GET / HTTP/1.1\nhost: a.b:8443\n\n"),
            Some(("a.b".into(), Some(8443)))
        );
        assert_eq!(
            host_header("GET / HTTP/1.1\nHost: [::1]:9\n\n"),
            Some(("::1".into(), Some(9)))
        );
        assert_eq!(host_header("GET / HTTP/1.1\n\n"), None);
    }
}
