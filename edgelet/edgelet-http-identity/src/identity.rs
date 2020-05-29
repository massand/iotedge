// Copyright (c) Microsoft. All rights reserved.

use crate::error::{Error, ErrorKind};
use edgelet_core::{AuthId, WorkloadConfig};
use edgelet_http::route::{Handler, Parameters};
use edgelet_http::Error as HttpError;
use failure::ResultExt;
use futures::{future, Future};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Body, Request, Response, StatusCode};

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

        let body = req
            .extensions()
            .get::<AuthId>()
            .map_or_else(
                || "AuthId expected".to_string(),
                |auth_id| format!("auth = {}", auth_id),
            )
            .into();

        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, "10")
            .body(body)
            .unwrap();

        Box::new(future::ok(response))
    }
}
