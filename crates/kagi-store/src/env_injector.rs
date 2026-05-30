use kagi_domain::error::DomainError;
use kagi_domain::runner::CommandRunner;
use std::process::Command;

pub struct SystemCommandRunner;

impl SystemCommandRunner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SystemCommandRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRunner for SystemCommandRunner {
    fn run(
        &self,
        env_vars: &[(String, String)],
        command: &str,
        args: &[String],
    ) -> Result<i32, DomainError> {
        let mut cmd = Command::new(command);
        cmd.args(args);
        for (key, value) in env_vars {
            cmd.env(key, value);
        }
        let status = cmd.status()?;
        Ok(status.code().unwrap_or(1))
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod mock {
    use kagi_domain::error::DomainError;
    use kagi_domain::runner::CommandRunner;
    use std::sync::{Arc, Mutex};

    type CallRecord = (Vec<(String, String)>, String, Vec<String>);

    #[derive(Default, Clone)]
    pub struct MockCommandRunner {
        pub calls: Arc<Mutex<Vec<CallRecord>>>,
        pub exit_code: i32,
    }

    impl CommandRunner for MockCommandRunner {
        fn run(
            &self,
            env_vars: &[(String, String)],
            command: &str,
            args: &[String],
        ) -> Result<i32, DomainError> {
            self.calls.lock().unwrap().push((
                env_vars.to_vec(),
                command.to_string(),
                args.to_vec(),
            ));
            Ok(self.exit_code)
        }
    }
}
