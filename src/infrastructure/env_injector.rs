use crate::domain::error::DomainError;
use crate::domain::runner::CommandRunner;

pub struct SystemCommandRunner;

impl SystemCommandRunner {
    pub fn new() -> Self {
        Self
    }
}

impl CommandRunner for SystemCommandRunner {
    fn run(
        &self,
        _env_vars: &[(String, String)],
        _command: &str,
        _args: &[String],
    ) -> Result<i32, DomainError> {
        todo!()
    }
}

#[cfg(test)]
pub mod mock {
    use crate::domain::error::DomainError;
    use crate::domain::runner::CommandRunner;
    use std::sync::{Arc, Mutex};

    #[derive(Default, Clone)]
    pub struct MockCommandRunner {
        pub calls: Arc<Mutex<Vec<(Vec<(String, String)>, String, Vec<String>)>>>,
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
