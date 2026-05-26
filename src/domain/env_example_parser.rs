pub struct ExampleEntry {
    pub key: String,
    pub value: String,
    pub is_commented: bool,
}

pub fn parse_env_example(content: &str) -> Vec<ExampleEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') {
            let after_hash = trimmed[1..].trim();
            if let Some(eq_pos) = after_hash.find('=') {
                let key = after_hash[..eq_pos].trim();
                if is_valid_key(key) {
                    let value = after_hash[eq_pos + 1..].trim();
                    entries.push(ExampleEntry {
                        key: key.to_string(),
                        value: value.to_string(),
                        is_commented: true,
                    });
                }
            }
        } else if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim();
            if is_valid_key(key) {
                let value = trimmed[eq_pos + 1..].trim();
                entries.push(ExampleEntry {
                    key: key.to_string(),
                    value: value.to_string(),
                    is_commented: false,
                });
            }
        }
    }
    entries
}

fn is_valid_key(key: &str) -> bool {
    !key.is_empty() && key.chars().all(|c| c.is_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_example_basic() {
        let content = "API_KEY=secret\nDEBUG=true\n";
        let entries = parse_env_example(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "API_KEY");
        assert_eq!(entries[0].value, "secret");
        assert!(!entries[0].is_commented);
        assert_eq!(entries[1].key, "DEBUG");
        assert_eq!(entries[1].value, "true");
        assert!(!entries[1].is_commented);
    }

    #[test]
    fn test_parse_example_commented() {
        let content = "# API_KEY=\n# DEBUG=false\n";
        let entries = parse_env_example(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "API_KEY");
        assert_eq!(entries[0].value, "");
        assert!(entries[0].is_commented);
        assert_eq!(entries[1].key, "DEBUG");
        assert_eq!(entries[1].value, "false");
        assert!(entries[1].is_commented);
    }

    #[test]
    fn test_parse_example_mixed() {
        let content = "DATABASE_URL=postgres://localhost\nAPI_KEY=\n# WEBHOOK_SECRET=\n";
        let entries = parse_env_example(content);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].key, "DATABASE_URL");
        assert_eq!(entries[0].value, "postgres://localhost");
        assert!(!entries[0].is_commented);
        assert_eq!(entries[1].key, "API_KEY");
        assert_eq!(entries[1].value, "");
        assert!(!entries[1].is_commented);
        assert_eq!(entries[2].key, "WEBHOOK_SECRET");
        assert_eq!(entries[2].value, "");
        assert!(entries[2].is_commented);
    }

    #[test]
    fn test_parse_example_skips_plain_comments() {
        let content = "# This is a comment\nKEY=val\n";
        let entries = parse_env_example(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "KEY");
    }

    #[test]
    fn test_parse_example_empty_lines() {
        let content = "KEY=val\n\n\nOTHER=x\n";
        let entries = parse_env_example(content);
        assert_eq!(entries.len(), 2);
    }
}
