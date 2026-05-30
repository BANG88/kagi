use kagi_domain::error::DomainError;
use kagi_domain::repository::secret_repo::SecretRepository;
use kagi_domain::runner::CommandRunner;

pub struct RunCommandService<R: SecretRepository, C: CommandRunner> {
    repo: R,
    runner: C,
}

impl<R: SecretRepository, C: CommandRunner> RunCommandService<R, C> {
    pub fn new(repo: R, runner: C) -> Self {
        Self { repo, runner }
    }

    pub fn execute(
        &self,
        service_name: &str,
        command: &str,
        args: &[String],
    ) -> Result<i32, DomainError> {
        let service = self.repo.load(service_name)?;
        let env_vars: Vec<_> = service
            .secrets
            .values()
            .map(|s| (s.key.clone(), s.value.clone()))
            .collect();
        self.runner.run(&env_vars, command, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagi_domain::crypto::encryptor::mock::XorEncryptor;
    use kagi_domain::entity::secret::Secret;
    use kagi_domain::entity::service::Service;
    use kagi_store::env_injector::mock::MockCommandRunner;
    use kagi_store::fs_store::FileStore;
    use tempfile::TempDir;

    fn setup(
        dir: &TempDir,
    ) -> (
        RunCommandService<FileStore, MockCommandRunner>,
        MockCommandRunner,
    ) {
        let base = dir.path().join(".kagi");
        std::fs::create_dir(&base).unwrap();
        let config = serde_json::json!({"version": "2", "project_id": "kgp_test", "services": {}});
        std::fs::write(
            base.join(kagi_domain::config::KAGI_CONFIG_FILE),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        let store = FileStore::new(base, Box::new(XorEncryptor::new(0xAB)));
        let mut svc = Service::new("api");
        svc.set_secret(Secret::new("KEY", "val"));
        store.save(&svc).unwrap();
        let runner = MockCommandRunner::default();
        (RunCommandService::new(store, runner.clone()), runner)
    }

    #[test]
    fn test_run_injects_env() {
        let dir = TempDir::new().unwrap();
        let (svc, runner) = setup(&dir);
        let exit_code = svc.execute("api", "echo", &["hello".into()]).unwrap();
        assert_eq!(exit_code, 0);
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, vec![("KEY".to_string(), "val".to_string())]);
        assert_eq!(calls[0].1, "echo");
    }
}
