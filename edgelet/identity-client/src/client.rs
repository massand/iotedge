// Copyright (c) Microsoft. All rights reserved.

use failure::{Fail, ResultExt};
use futures::future::Future;
use futures::prelude::*;
use hyper::client::{Client as HyperClient};
use hyper::{Body, Client};
use typed_headers::{self, http};

use edgelet_http::{UrlConnector};

use crate::error::{Error, ErrorKind, RequestType};
use url::Url;

#[derive(Clone)]
pub struct IdentityClient {
    client: HyperClient<UrlConnector, Body>,
    host: Url,
}

impl IdentityClient {
    pub fn new() -> Result<Self, Error> {
        //TODO: Read IS endpoint configuration
        
        let url = Url::parse("http://localhost:8901").map_err(|err| Error::from(ErrorKind::Uri(err)))?;
        let client = Client::builder()
            .build(UrlConnector::new(
                &url).context(ErrorKind::Hyper)?);
        Ok(IdentityClient {
            client,
            host: url,
        })
    }

    pub fn get_device(
        &self,
        _api_version: &str,
    ) -> Box<dyn Future<Item = aziot_identity_common::Identity, Error = Error> + Send>
    {
        let uri = format!("{}identities/device", self.host.as_str());
        let body = serde_json::json! {{ "type": "aziot" }};

        request(
            &self.client,
            hyper::Method::POST,
            &uri,
            Some(&body),
        )
    }
    
    pub fn reprovision_device(
        &self,
        _api_version: &str,
    ) -> Box<dyn Future<Item = (), Error = Error> + Send> 
    {
        let uri = format!("{}identities/device/reprovision", self.host.as_str());
        let body = serde_json::json! {{ "type": "aziot" }};

        request(
            &self.client,
            hyper::Method::POST,
            &uri,
            Some(&body),
        )
    }

    pub fn create_module(
        &self,
        _api_version: &str,
        module_name: &str,
    ) -> Box<dyn Future<Item = aziot_identity_common::Identity, Error = Error> + Send>
    {
        let uri = format!("{}identities/modules", self.host.as_str());
        let body = serde_json::json! {{ "type": "aziot", "moduleId" : module_name }};

        request(
            &self.client,
            hyper::Method::POST,
            &uri,
            Some(&body),
        )
    }

    pub fn delete_module(
        &self,
        _api_version: &str,
        module_name: &str,
    ) -> Box<dyn Future<Item = (), Error = Error> + Send> 
    {       
        let uri = format!("{}identities/modules/{}", self.host.as_str(), module_name);

        request::<_, (), _>(
            &self.client,
            hyper::Method::DELETE,
            &uri,
            None,
        )
    }

    pub fn get_module(
        &self,
        _api_version: &str,
        module_name: &str,
    ) -> Box<dyn Future<Item = aziot_identity_common::Identity, Error = Error> + Send>
    {
        let uri = format!("{}identities/modules/{}", self.host.as_str(), module_name);
        let body = serde_json::json! {{ "type": "aziot", "moduleId" : module_name }};

        request(
            &self.client,
            hyper::Method::GET,
            &uri,
            Some(&body),
        )
    }

    pub fn get_modules(
        &self,
        _api_version: &str,
    ) -> Box<dyn Future<Item = Vec<aziot_identity_common::Identity>, Error = Error> + Send> 
    {
        let uri = format!("{}identities/modules", self.host.as_str());

        request::<_, (), _>(
            &self.client,
            hyper::Method::POST,
            &uri,
            None,
        )
    }
}

fn request<TConnect, TRequest, TResponse>(
    client: &hyper::Client<TConnect, hyper::Body>,
    method: http::Method,
    uri: &str,
    body: Option<&TRequest>,
) -> Box<dyn Future<Item = TResponse, Error = Error> + Send>
where
    TConnect: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    TRequest: serde::Serialize,
    TResponse: serde::de::DeserializeOwned + Send + 'static,
{
    let mut builder = hyper::Request::builder();
    builder.method(method).uri(uri);
    
    let builder =
    if let Some(body) = body {
        let body = serde_json::to_vec(body).expect("serializing request body to JSON cannot fail").into();
        builder
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(body)
    }
    else {
        builder.body(Default::default())
    };
    
    let req = builder.expect("cannot fail to create hyper request");
    
    Box::new(
        client
        .request(req)
        .map_err(|e| Error::from(e.context(ErrorKind::Request)))
        .and_then(|resp| {
            let (http::response::Parts { status, .. }, body) = resp.into_parts();
            body.concat2()
                .and_then(move |body| Ok((status, body)))
                .map_err(|e| Error::from(e.context(ErrorKind::Hyper)))
        })
        .and_then(|(status, body)| {
            if status.is_success() {
                Ok(body)
            } else {
                Err(Error::http_with_error_response(status, &*body))
            }
        })
        .and_then(|body| {
            let parsed: Result<TResponse, _> =
                serde_json::from_slice(&body);
            parsed.map_err(|e| Error::from(e.context(ErrorKind::JsonParse(RequestType::ListModules))))
        })
    )
}
