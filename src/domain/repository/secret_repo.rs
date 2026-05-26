use crate::domain::entity::service::Service;
use crate::domain::error::DomainError;

pub trait SecretRepository: Send + Sync {
    fn load(&self, service_name: &str) -> Result<Service, DomainError>;
    fn save(&self, service: &Service) -> Result<(), DomainError>;
    fn list_services(&self) -> Result<Vec<String>, DomainError>;
}
