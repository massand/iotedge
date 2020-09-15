// Copyright (c) Microsoft. All rights reserved.

use std::sync::{Arc, Mutex};

use failure::ResultExt;
use futures::{Future, IntoFuture, Stream};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Body, Request, Response, StatusCode};
use workload::models::{SignRequest, SignResponse};

use edgelet_core::crypto::{KeyIdentity, KeyStore, Sign, Signature, SignatureAlgorithm};
use edgelet_http::route::{Handler, Parameters};
use edgelet_http::Error as HttpError;
use http_common::Connector;

use crate::error::{EncryptionOperation, Error, ErrorKind};
use crate::IntoResponse;

pub struct SignHandler
{
    key_store: Arc<Mutex<aziot_key_client::Client>>,
}

impl SignHandler
{
    pub fn new(key_connector: Connector) -> Self {
        let key_store = Arc::new(Mutex::new(aziot_key_client::Client::new(key_connector)));
        
        SignHandler { key_store }
    }
}

// pub fn sign<K: KeyStore>(
//     key_store: &K,
//     id: String,
//     request: &SignRequest,
// ) -> Result<SignResponse, Error> {
//     let k = key_store
//         .get(&KeyIdentity::Module(id.clone()), request.key_id())
//         .context(ErrorKind::ModuleNotFound(id))?;
//     let data: Vec<u8> = base64::decode(request.data()).context(ErrorKind::MalformedRequestBody)?;
//     let signature = k
//         .sign(SignatureAlgorithm::HMACSHA256, &data)
//         .context(ErrorKind::EncryptionOperation(EncryptionOperation::Sign))?;
//     let encoded = base64::encode(signature.as_bytes());
//     Ok(SignResponse::new(encoded))
// }

impl Handler<Parameters> for SignHandler
{
    fn handle(
        &self,
        req: Request<Body>,
        params: Parameters,
    ) -> Box<dyn Future<Item = Response<Body>, Error = HttpError> + Send> {
        let key_store = self.key_store.clone();
        let response = params
            .name("name")
            .ok_or_else(|| Error::from(ErrorKind::MissingRequiredParameter("name")))
            .and_then(|name| {
                let genid = params
                    .name("genid")
                    .ok_or_else(|| Error::from(ErrorKind::MissingRequiredParameter("genid")))?;
                Ok((name, genid))
            })
            .map(|(name, genid)| {
                let id = name.to_string();
                let genid = genid.to_string();
                let key_store = self.key_store.clone();

                req.into_body().concat2().then(|body| {
                    let body =
                        body.context(ErrorKind::EncryptionOperation(EncryptionOperation::Encrypt))?;
                    Ok((id, genid, key_store, body))
                })
            })
            .into_future()
            .flatten()
            .and_then(|(id, genid, key_store, body)| -> Result<_, Error> {
                let key_store = key_store.lock().unwrap();
                let request: SignRequest =
                    serde_json::from_slice(&body).context(ErrorKind::MalformedRequestBody)?;
                let key_id = format!("{}{}", request.key_id(), genid);
                //TODO: Need to call IS to get key handle for derived key and use the derived key to sign data (see example in demo_module branch)
                // let response = sign(&key_store, id, &request.with_key_id(key_id))?;
                let k = key_store
                    .get(&KeyIdentity::Module(id.clone()), request.key_id())
                    .context(ErrorKind::ModuleNotFound(id))?;
                let data: Vec<u8> = base64::decode(request.data()).context(ErrorKind::MalformedRequestBody)?;
                let signature = k
                    .sign(SignatureAlgorithm::HMACSHA256, &data)
                    .context(ErrorKind::EncryptionOperation(EncryptionOperation::Sign))?;
                let encoded = base64::encode(signature.as_bytes());
                let response = SignResponse::new(encoded);
                let body = serde_json::to_string(&response)
                    .context(ErrorKind::EncryptionOperation(EncryptionOperation::Sign))?;
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .header(CONTENT_LENGTH, body.len().to_string().as_str())
                    .body(body.into())
                    .context(ErrorKind::EncryptionOperation(EncryptionOperation::Sign))?;
                Ok(response)
            })
            .or_else(|e| Ok(e.into_response()));

        Box::new(response)
    }
}
