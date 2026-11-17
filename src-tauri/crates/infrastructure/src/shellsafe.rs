//! Shared shell safety and name validation helpers.

use domain::DomainError;

/// Validates and single-quote escapes a remote path to prevent shell injection.
pub fn validate_safe_remote_path(path: &str) -> Result<String, DomainError> {
    if path
        .chars()
        .any(|c| matches!(c, ';' | '&' | '|' | '`' | '$' | '(' | ')' | '\n' | '\r'))
    {
        return Err(DomainError::Validation {
            field: "path".into(),
            message: "path contains disallowed shell characters".into(),
        });
    }
    let escaped = path.replace('\'', "'\\''");
    Ok(format!("'{escaped}'"))
}

/// Validates a container ID or container name string.
pub fn validate_container_id(id: &str) -> Result<&str, DomainError> {
    // A leading '-' would be parsed as a CLI option (`docker logs --follow`).
    let valid = !id.is_empty()
        && !id.starts_with('-')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if !valid {
        return Err(DomainError::Validation {
            field: "container_id".into(),
            message: "invalid container ID or name format".into(),
        });
    }
    Ok(id)
}

/// Validates a systemd unit name string.
pub fn validate_systemd_unit(unit: &str) -> Result<(), DomainError> {
    let valid = !unit.is_empty()
        && !unit.starts_with('-')
        && unit.len() <= 256
        && unit
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'));
    if !valid {
        return Err(DomainError::Validation {
            field: "unit".into(),
            message: "invalid systemd unit name".into(),
        });
    }
    Ok(())
}

/// Validates a Kubernetes resource name or namespace string.
pub fn validate_k8s_name<'a>(
    name: &'a str,
    field_name: &'static str,
) -> Result<&'a str, DomainError> {
    let valid = !name.is_empty()
        && !name.starts_with('-')
        && name.len() <= 253
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    if !valid {
        return Err(DomainError::Validation {
            field: field_name.into(),
            message: format!("invalid {field_name} format"),
        });
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_path_is_quoted() {
        assert_eq!(validate_safe_remote_path("/var/www").unwrap(), "'/var/www'");
        assert_eq!(
            validate_safe_remote_path("/tmp/it's").unwrap(),
            "'/tmp/it'\\''s'"
        );
    }

    #[test]
    fn remote_path_rejects_shell_metacharacters() {
        for bad in [
            "/a; rm -rf /",
            "/a && id",
            "/a | sh",
            "/`id`",
            "/$(id)",
            "/a\nid",
        ] {
            assert!(validate_safe_remote_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn container_ids() {
        assert!(validate_container_id("web_1.prod-a").is_ok());
        for bad in ["", "a b", "a;id", "--follow", "-f", "$(id)"] {
            assert!(validate_container_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn systemd_units() {
        assert!(validate_systemd_unit("getty@tty1.service").is_ok());
        for bad in ["", "-x", "a b", "a;b"] {
            assert!(validate_systemd_unit(bad).is_err(), "{bad:?}");
        }
        assert!(validate_systemd_unit(&"a".repeat(257)).is_err());
    }

    #[test]
    fn k8s_names() {
        assert!(validate_k8s_name("kube-system", "namespace").is_ok());
        for bad in ["", "-A", "--kubeconfig", "a_b", "a/b", "a b"] {
            assert!(validate_k8s_name(bad, "namespace").is_err(), "{bad:?}");
        }
    }
}
