use std::sync::Arc;

use super::configuration::Configuration;
use hyper;

pub struct APIClient {
    device_identity_api: Box<dyn crate::apis::DeviceIdentityApi>,
    module_identity_api: Box<dyn crate::apis::ModuleIdentityApi>,
    workload_operations_api: Box<dyn crate::apis::WorkloadOperationsApi>,
}

impl APIClient {
    pub fn new<C>(configuration: Configuration<C>) -> Self
    where
        C: hyper::client::connect::Connect + 'static,
    {
        let configuration = Arc::new(configuration);

        APIClient {
            device_identity_api: Box::new(crate::apis::DeviceIdentityApiClient::new(
                configuration.clone(),
            )),
            module_identity_api: Box::new(crate::apis::ModuleIdentityApiClient::new(
                configuration.clone(),
            )),
            workload_operations_api: Box::new(crate::apis::WorkloadOperationsApiClient::new(
                configuration.clone(),
            )),
        }
    }

    pub fn device_identity_api(&self) -> &dyn crate::apis::DeviceIdentityApi {
        self.device_identity_api.as_ref()
    }

    pub fn module_identity_api(&self) -> &dyn crate::apis::ModuleIdentityApi {
        self.module_identity_api.as_ref()
    }

    pub fn workload_operations_api(&self) -> &dyn crate::apis::WorkloadOperationsApi {
        self.workload_operations_api.as_ref()
    }
}
