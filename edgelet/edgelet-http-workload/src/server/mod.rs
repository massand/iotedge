// Copyright (c) Microsoft. All rights reserved.

mod cert;
mod decrypt;
mod encrypt;
mod sign;
mod trust_bundle;

use aziot_key_client::Client as KeyClient;
use aziot_key_common::KeyHandle;
use cert_client::client::CertificateClient;
use edgelet_core::{
    Authenticator, Module, ModuleRuntime, ModuleRuntimeErrorReason, Policy, WorkloadConfig,
};
use edgelet_http::authentication::Authentication;
use edgelet_http::authorization::Authorization;
use edgelet_http::route::{Builder, RegexRecognizer, Router, RouterService};
use edgelet_http::{router, Version};
use edgelet_http_mgmt::ListModules;
use identity_client::client::IdentityClient;

use failure::{Compat, Fail, ResultExt};
use futures::{future, Future, IntoFuture};
use hyper::service::{NewService, Service};
use hyper::{Body, Request};
use serde::Serialize;
use std::sync::{Arc, Mutex};

use self::cert::{IdentityCertHandler, ServerCertHandler};
use self::decrypt::DecryptHandler;
use self::encrypt::EncryptHandler;
use self::sign::SignHandler;
use self::trust_bundle::TrustBundleHandler;
use crate::error::{Error, ErrorKind};

#[derive(Clone)]
pub struct WorkloadService {
    inner: RouterService<RegexRecognizer>,
}

impl WorkloadService {
    pub fn new<M, W>(
        runtime: &M,
        identity_client: Arc<Mutex<IdentityClient>>,
        cert_client: Arc<Mutex<CertificateClient>>,
        key_connector: http_common::Connector,
        config: W,
    ) -> impl Future<Item = Self, Error = Error>
    where
        M: ModuleRuntime + Authenticator<Request = Request<Body>> + Clone + Send + Sync + 'static,
        for<'r> &'r <M as ModuleRuntime>::Error: Into<ModuleRuntimeErrorReason>,
        <M::Module as Module>::Config: Serialize,
        M::Logs: Into<Body>,
        W: WorkloadConfig + Clone + Send + Sync + 'static,
        <M::AuthenticateFuture as Future>::Error: Fail,
    {
        let router = router!(
            get   Version2018_06_28 runtime Policy::Anonymous => "/modules" => ListModules::new(runtime.clone()),
            post  Version2018_06_28 runtime Policy::Caller =>    "/modules/(?P<name>[^/]+)/genid/(?P<genid>[^/]+)/sign"     => SignHandler::new(identity_client, key_connector.clone()),
            post  Version2018_06_28 runtime Policy::Caller =>    "/modules/(?P<name>[^/]+)/genid/(?P<genid>[^/]+)/decrypt"  => DecryptHandler::new(key_connector.clone()),
            post  Version2018_06_28 runtime Policy::Caller =>    "/modules/(?P<name>[^/]+)/genid/(?P<genid>[^/]+)/encrypt"  => EncryptHandler::new(key_connector.clone()),
            post  Version2018_06_28 runtime Policy::Caller =>    "/modules/(?P<name>[^/]+)/certificate/identity"            => IdentityCertHandler::new(cert_client.clone(), key_connector. clone(), config.clone()),
            post  Version2018_06_28 runtime Policy::Caller =>    "/modules/(?P<name>[^/]+)/genid/(?P<genid>[^/]+)/certificate/server" => ServerCertHandler::new(cert_client.clone(), key_connector, config),

            get   Version2018_06_28 runtime Policy::Anonymous => "/trust-bundle" => TrustBundleHandler::new(cert_client),
        );

        router.new_service().then(|inner| {
            let inner = inner.context(ErrorKind::StartService)?;
            Ok(WorkloadService { inner })
        })
    }
}

impl Service for WorkloadService {
    type ReqBody = <RouterService<RegexRecognizer> as Service>::ReqBody;
    type ResBody = <RouterService<RegexRecognizer> as Service>::ResBody;
    type Error = <RouterService<RegexRecognizer> as Service>::Error;
    type Future = <RouterService<RegexRecognizer> as Service>::Future;

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        self.inner.call(req)
    }
}

impl NewService for WorkloadService {
    type ReqBody = <Self::Service as Service>::ReqBody;
    type ResBody = <Self::Service as Service>::ResBody;
    type Error = <Self::Service as Service>::Error;
    type Service = Self;
    type Future = future::FutureResult<Self::Service, Self::InitError>;
    type InitError = Compat<Error>;

    fn new_service(&self) -> Self::Future {
        future::ok(self.clone())
    }
}

fn get_derived_identity_key_handle(
    identity_client: &Arc<Mutex<IdentityClient>>,
    name: &str,
) -> impl Future<Item = KeyHandle, Error = Error> {
    let id_client = identity_client.lock().unwrap();
    id_client.get_module(name).then(|identity| match identity {
        Ok(aziot_identity_common::Identity::Aziot(spec)) => spec
            .auth
            .and_then(|authinfo| authinfo.key_handle)
            .ok_or_else(|| failure::err_msg("keyhandle missing"))
            .context(ErrorKind::GetIdentity)
            .map_err(Into::into),
        Ok(aziot_identity_common::Identity::Local(_)) => {
            Err(Error::from(ErrorKind::InvalidIdentityType))
        }
        Err(err) => Err(err.context(ErrorKind::GetIdentity).into()),
    })
}

fn get_master_encryption_key(
    key_client: &Arc<KeyClient>,
) -> impl Future<Item = KeyHandle, Error = Error> {
    key_client
        .create_key_if_not_exists(
            "iotedge_master_encryption_id",
            aziot_key_common::CreateKeyValue::Generate { length: 32 },
        )
        .map_err(|_| Error::from(ErrorKind::LoadMasterEncKey))
        .into_future()
}

fn get_derived_enc_key_handle(
    key_client: Arc<KeyClient>,
    name: String,
) -> impl Future<Item = KeyHandle, Error = Error> {
    get_master_encryption_key(&key_client).and_then(move |key_handle| {
        key_client
            .create_derived_key(&key_handle, name.as_bytes())
            .map_err(|_| Error::from(ErrorKind::GetIdentity))
    })
}
