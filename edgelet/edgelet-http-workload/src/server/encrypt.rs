// Copyright (c) Microsoft. All rights reserved.
use std::sync::{Arc, Mutex};

use failure::ResultExt;
use futures::{Future, IntoFuture, Stream};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Body, Request, Response, StatusCode};

use edgelet_core::Encrypt;
use edgelet_http::route::{Handler, Parameters};
use edgelet_http::Error as HttpError;
use http_common::Connector;
use identity_client::client::IdentityClient;
use workload::models::{EncryptRequest, EncryptResponse};

use crate::error::{EncryptionOperation, Error, ErrorKind};
use crate::IntoResponse;

pub struct EncryptHandler {
    key_store: Arc<Mutex<aziot_key_client::Client>>,
    identity_client: Arc<Mutex<IdentityClient>>,
}

impl EncryptHandler {
    pub fn new(key_connector: Connector, identity_client: IdentityClient) -> Self {
        let key_store = Arc::new(Mutex::new(aziot_key_client::Client::new(key_connector)));
        
        EncryptHandler { key_store, identity_client: Arc::new(Mutex::new(identity_client)) }
    }
}

impl Handler<Parameters> for EncryptHandler
where
    T: Encrypt + 'static + Clone + Send + Sync,
{
    fn handle(
        &self,
        req: Request<Body>,
        params: Parameters,
    ) -> Box<dyn Future<Item = Response<Body>, Error = HttpError> + Send> {
        let hsm = self.hsm.clone();

        let response = params
            .name("name")
            .ok_or_else(|| Error::from(ErrorKind::MissingRequiredParameter("name")))
            .and_then(|name| {
                let genid = params
                    .name("genid")
                    .ok_or_else(|| Error::from(ErrorKind::MissingRequiredParameter("genid")))?;
                Ok((name, genid))
            })
            .map(|(module_id, genid)| {
                let id = format!("{}{}", module_id.to_string(), genid.to_string());
                req.into_body().concat2().then(|body| {
                    let body =
                        body.context(ErrorKind::EncryptionOperation(EncryptionOperation::Encrypt))?;
                    Ok((id, body))
                })
            })
            .into_future()
            .flatten()
            .and_then(move |(id, body)| -> Result<_, Error> {
                let request: EncryptRequest =
                    serde_json::from_slice(&body).context(ErrorKind::MalformedRequestBody)?;
                let plaintext =
                    base64::decode(request.plaintext()).context(ErrorKind::MalformedRequestBody)?;
                let initialization_vector = base64::decode(request.initialization_vector())
                    .context(ErrorKind::MalformedRequestBody)?;
                let ciphertext = hsm
                    .encrypt(id.as_bytes(), &plaintext, &initialization_vector)
                    .context(ErrorKind::EncryptionOperation(EncryptionOperation::Encrypt))?;
                let encoded = base64::encode(&ciphertext);
                let response = EncryptResponse::new(encoded);
                let body = serde_json::to_string(&response)
                    .context(ErrorKind::EncryptionOperation(EncryptionOperation::Encrypt))?;
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .header(CONTENT_LENGTH, body.len().to_string().as_str())
                    .body(body.into())
                    .context(ErrorKind::EncryptionOperation(EncryptionOperation::Encrypt))?;
                Ok(response)
            })
            .or_else(|e| Ok(e.into_response()));

        Box::new(response)
    }
}

