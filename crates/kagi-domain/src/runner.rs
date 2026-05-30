use crate::error::DomainError;

pub trait CommandRunner: Send + Sync {
    fn run(
        &self,
        env_vars: &[(String, String)],
        command: &str,
        args: &[String],
    ) -> Result<i32, DomainError>;
}
