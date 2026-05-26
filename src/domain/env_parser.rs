pub fn parse_dotenv(content: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(pos) = line.find('=') {
            let key = line[..pos].trim().to_string();
            let value = line[pos + 1..].trim().to_string();
            // Strip surrounding quotes if present
            let value = if (value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))
            {
                value[1..value.len() - 1].to_string()
            } else {
                value
            };
            if !key.is_empty() {
                result.push((key, value));
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
                ("API_KEY".into(), "secret".into()),
                ("DB_URL".into(), "postgres://localhost".into()),
            ]
        );
    }

    #[test]
    fn test_parse_skip_comments_and_empty() {
        let content = "\n# comment\nKEY=value\n  \n";
        let vars = parse_dotenv(content);
        assert_eq!(vars, vec![("KEY".into(), "value".into())]);
    }

    #[test]
    fn test_parse_quoted() {
        let content = r#"KEY="quoted value""#;
        let vars = parse_dotenv(content);
        assert_eq!(vars, vec![("KEY".into(), "quoted value".into())]);
    }

    #[test]
    fn test_parse_value_with_equals() {
        let content = "KEY=val=ue=with=equals\n";
        let vars = parse_dotenv(content);
        assert_eq!(vars, vec![("KEY".into(), "val=ue=with=equals".into())]);
    }
}
