// Copyright (c) Microsoft. All rights reserved.

use crate::error::{Error, ErrorKind};
use edgelet_core::WorkloadConfig;
use edgelet_http::route::{Handler, Parameters};
use edgelet_http::Error as HttpError;
use failure::ResultExt;
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
        _req: Request<Body>,
        _params: Parameters,
    ) -> Box<dyn Future<Item = Response<Body>, Error = HttpError> + Send> {
        let _config = self.config.clone();

        let identity_auth =
            identity::models::Credentials::new("sas".to_string(), "primary".to_string());
        let identity_spec = IdentitySpec::new(
            _config.iot_hub_name().to_string(),
            _config.device_id().to_string(),
            identity_auth,
        );
        let mut identity_result = IdentityResult::new("aziot".to_string());
        identity_result.set_spec(identity_spec);

        let body = serde_json::to_string(&identity_result)
            .context(ErrorKind::GetIdentity)
            .unwrap();

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
