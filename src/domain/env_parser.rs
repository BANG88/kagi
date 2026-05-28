pub fn parse_dotenv(content: &str) -> Vec<(String, String, Option<String>)> {
    let mut result = Vec::new();
    let mut last_comment: Option<String> = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            last_comment = None;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('#') {
            let comment = rest.trim().to_string();
            if !comment.is_empty() {
                last_comment = Some(comment);
            }
            continue;
        }
        if let Some(pos) = trimmed.find('=') {
            let key = trimmed[..pos].trim().to_string();
            let value = trimmed[pos + 1..].trim().to_string();
            // Strip surrounding quotes if present
            let value = if (value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))
            {
                value[1..value.len() - 1].to_string()
            } else {
                value
            };
            if !key.is_empty() {
                result.push((key, value, last_comment.take()));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic() {
        let content = "API_KEY=secret\nDB_URL=postgres://localhost\n";
        let vars = parse_dotenv(content);
        assert_eq!(
            vars,
            vec![
                ("API_KEY".into(), "secret".into(), None),
                ("DB_URL".into(), "postgres://localhost".into(), None),
            ]
        );
    }

    #[test]
    fn test_parse_skip_comments_and_empty() {
        let content = "\n# comment\nKEY=value\n  \n";
        let vars = parse_dotenv(content);
        assert_eq!(
            vars,
            vec![("KEY".into(), "value".into(), Some("comment".into()))]
        );
    }

    #[test]
    fn test_parse_quoted() {
        let content = r#"KEY="quoted value""#;
        let vars = parse_dotenv(content);
        assert_eq!(vars, vec![("KEY".into(), "quoted value".into(), None)]);
    }

    #[test]
    fn test_parse_value_with_equals() {
        let content = "KEY=val=ue=with=equals\n";
        let vars = parse_dotenv(content);
        assert_eq!(
            vars,
            vec![("KEY".into(), "val=ue=with=equals".into(), None)]
        );
    }

    #[test]
    fn test_parse_description_from_comment() {
        let content =
            "# Database URL\nDB_URL=postgres://localhost\n# API key for staging\nAPI_KEY=secret\n";
        let vars = parse_dotenv(content);
        assert_eq!(
            vars,
            vec![
                (
                    "DB_URL".into(),
                    "postgres://localhost".into(),
                    Some("Database URL".into())
                ),
                (
                    "API_KEY".into(),
                    "secret".into(),
                    Some("API key for staging".into())
                ),
            ]
        );
    }
}
