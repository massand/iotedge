// Copyright (c) Microsoft. All rights reserved.

use crate::error::{Error, ErrorKind};
use edgelet_core::{AuthId, WorkloadConfig};
use edgelet_http::route::{Handler, Parameters};
use edgelet_http::Error as HttpError;
use failure::{ResultExt, Fail};
use futures::{future, Future};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Body, Request, Response, StatusCode};
use identity::models::{IdentityResult, IdentitySpec};

use crate::IntoResponse;

pub struct IdentityHandler<W: WorkloadConfig> {
    config: W,
}

impl<W: WorkloadConfig> IdentityHandler<W> {
    pub fn new(config: W) -> Self {
        IdentityHandler { config }
    }
}

impl<W> Handler<Parameters> for IdentityHandler<W>
where
    W: WorkloadConfig + Clone + Send + Sync + 'static,
{
    fn handle(
        &self,
        req: Request<Body>,
        _params: Parameters,
    ) -> Box<dyn Future<Item = Response<Body>, Error = HttpError> + Send> {
        let _config = self.config.clone();

        let identityauth = identity::models::Credentials::new("sas".to_string(), "primary".to_string());
        let identityspec = IdentitySpec::new(_config.iot_hub_name().to_string(), _config.device_id().to_string(), identityauth);
        let mut identityresult = IdentityResult::new("aziot".to_string());
        identityresult.set_spec(identityspec);

        let body = serde_json::to_string(&identityresult).context(
            ErrorKind::GetIdentity
        ).unwrap();

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len().to_string().as_str())
            .body(body.into())
            .context(ErrorKind::GetIdentity)
            .unwrap();

        Box::new(future::ok(response))
    }
}
