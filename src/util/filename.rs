/// Sanitize a string for use as a filename.
/// Routes all filename construction through the sanitize-filename crate.
/// Must be called before any file-write code (per STATE.md constraint).
pub fn sanitize_filename(name: &str) -> String {
    let opts = sanitize_filename::Options {
        replacement: "_",
        ..Default::default()
    };
    let sanitized = sanitize_filename::sanitize_with_options(name, opts);
    if sanitized.is_empty() {
        "_unnamed".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_filename_removes_slashes_and_colons() {
        let result = sanitize_filename("192.168.1.1:80/tcp");
        assert!(!result.contains('/'));
        assert!(!result.contains(':'));
        assert!(!result.is_empty());
    }

    #[test]
    fn sanitize_filename_empty_string_returns_fallback() {
        let result = sanitize_filename("");
        assert!(!result.is_empty());
        assert_eq!(result, "_unnamed");
    }

    #[test]
    fn sanitize_filename_normal_name_passes_through() {
        let result = sanitize_filename("192.168.1.1");
        assert_eq!(result, "192.168.1.1");
    }

    #[test]
    fn sanitize_filename_replaces_invalid_chars_with_underscore() {
        let result = sanitize_filename("host:443/https");
        // Slashes and colons should be replaced
        assert!(!result.contains('/'));
        assert!(!result.contains(':'));
    }
}
