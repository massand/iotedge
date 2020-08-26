// Copyright (c) Microsoft. All rights reserved.

use failure::{Fail, ResultExt};
use futures::future::Future;
use futures::prelude::*;
use hyper::client::{Client as HyperClient};
// use hyper::header::HeaderValue;
// use hyper::service::Service;
use hyper::{Body, Client};
// use hyper::{Body, Error as HyperError};
// use hyper::{Request, Uri};
// use log::{debug, trace};
use typed_headers::{self, http};

use edgelet_http::{UrlConnector};

use crate::error::{Error, ErrorKind, RequestType};
use url::Url;

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
        let method = hyper::Method::POST;
        
        let uri = format!("{}identities/device", self.host.as_str());

        let mut builder = hyper::Request::builder();
        builder.method(method).uri(uri);
        
        let body = serde_json::json! {{ "type": "aziot" }};
        let req = builder
            .body(hyper::Body::from(body.to_string()))
            .expect("could not build hyper::Request");
        
        Box::new(
            self
            .client
            .request(req)
            .map_err(|e| Error::from(e.context(ErrorKind::Request(RequestType::GetDevice))))
            .and_then(|resp| {
                let (http::response::Parts { status, .. }, body) = resp.into_parts();
                body.concat2()
                    .and_then(move |body| Ok((status, body)))
                    .map_err(|e| Error::from(e.context(ErrorKind::Response(RequestType::GetDevice))))
            })
            .and_then(|(status, body)| {
                if status.is_success() {
                    Ok(body)
                } else {
                    Err(Error::from(ErrorKind::Response(RequestType::GetDevice)))
                    //Err(Error::from((status, &*body)))
                }
            })
            .and_then(|body| {
                let parsed: Result<aziot_identity_common::Identity, _> =
                    serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e.context(ErrorKind::JsonParse(RequestType::GetDevice))))
            })
        )
    }
    
    pub fn reprovision_device(
        &self,
        _api_version: &str,
    ) -> Box<dyn Future<Item = (), Error = Error> + Send> 
    {
        let method = hyper::Method::POST;
        
        let uri = format!("{}identities/device/reprovision", self.host.as_str());

        let mut builder = hyper::Request::builder();
        builder.method(method).uri(uri);
        
        let body = serde_json::json! {{ "type": "aziot" }};
        let req = builder
            .body(hyper::Body::from(body.to_string()))
            .expect("could not build hyper::Request");
        
        Box::new(
            self
            .client
            .request(req)
            .map_err(|e| Error::from(e.context(ErrorKind::Request(RequestType::ReprovisionDevice))))
            .and_then(|resp| {
                let (http::response::Parts { status, .. }, body) = resp.into_parts();
                body.concat2()
                    .and_then(move |body| Ok((status, body)))
                    .map_err(|e| Error::from(e.context(ErrorKind::Response(RequestType::ReprovisionDevice))))
            })
            .and_then(|(status, _)| {
                if !status.is_success() {
                    Ok(())
                } else {
                    Err(Error::from(ErrorKind::Response(RequestType::ReprovisionDevice)))
                    //Err(Error::from((status, &*body)))
                }
            })
        )
    }

    pub fn create_module(
        &self,
        _api_version: &str,
        module_name: &str,
    ) -> Box<dyn Future<Item = aziot_identity_common::Identity, Error = Error> + Send>
    {
        let method = hyper::Method::POST;
        
        let uri = format!("{}identities/modules", self.host.as_str());

        let mut builder = hyper::Request::builder();
        builder.method(method).uri(uri);
        
        let body = serde_json::json! {{ "type": "aziot", "moduleId" : module_name }};
        let req = builder
            .body(hyper::Body::from(body.to_string()))
            .expect("could not build hyper::Request");
        
        Box::new(
            self
            .client
            .request(req)
            .map_err(|e| Error::from(e.context(ErrorKind::Request(RequestType::CreateModule))))
            .and_then(|resp| {
                let (http::response::Parts { status, .. }, body) = resp.into_parts();
                body.concat2()
                    .and_then(move |body| Ok((status, body)))
                    .map_err(|e| Error::from(e.context(ErrorKind::Response(RequestType::CreateModule))))
            })
            .and_then(|(status, body)| {
                if status.is_success() {
                    Ok(body)
                } else {
                    Err(Error::from(ErrorKind::Response(RequestType::CreateModule)))
                    //Err(Error::from((status, &*body)))
                }
            })
            .and_then(|body| {
                let parsed: Result<aziot_identity_common::Identity, _> =
                    serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e.context(ErrorKind::JsonParse(RequestType::CreateModule))))
            })
        )
    }

    pub fn delete_module(
        &self,
        _api_version: &str,
        module_name: &str,
    ) -> Box<dyn Future<Item = (), Error = Error> + Send> 
    {
        let method = hyper::Method::POST;
        
        let uri = format!("{}identities/modules", self.host.as_str());

        let mut builder = hyper::Request::builder();
        builder.method(method).uri(uri);
        
        let body = serde_json::json! {{ "type": "aziot", "moduleId" : module_name }};
        let req = builder
            .body(hyper::Body::from(body.to_string()))
            .expect("could not build hyper::Request");
        
        Box::new(
            self
            .client
            .request(req)
            .map_err(|e| Error::from(e.context(ErrorKind::Request(RequestType::DeleteModule))))
            .and_then(|resp| {
                let (http::response::Parts { status, .. }, body) = resp.into_parts();
                body.concat2()
                    .and_then(move |body| Ok((status, body)))
                    .map_err(|e| Error::from(e.context(ErrorKind::Response(RequestType::DeleteModule))))
            })
            .and_then(|(status, _)| {
                if !status.is_success() {
                    Ok(())
                } else {
                    Err(Error::from(ErrorKind::Response(RequestType::DeleteModule)))
                    //Err(Error::from((status, &*body)))
                }
            })
        )
    }

    pub fn get_module(
        &self,
        _api_version: &str,
        module_name: &str,
    ) -> Box<dyn Future<Item = aziot_identity_common::Identity, Error = Error> + Send>
    {
        let method = hyper::Method::GET;
        
        let uri = format!("{}identities/modules/{}", self.host.as_str(), module_name);

        let mut builder = hyper::Request::builder();
        builder.method(method).uri(uri);
        
        let body = serde_json::json! {{ "type": "aziot", "moduleId" : module_name }};
        let req = builder
            .body(hyper::Body::from(body.to_string()))
            .expect("could not build hyper::Request");
        
        Box::new(
            self
            .client
            .request(req)
            .map_err(|e| Error::from(e.context(ErrorKind::Request(RequestType::GetModule))))
            .and_then(|resp| {
                let (http::response::Parts { status, .. }, body) = resp.into_parts();
                body.concat2()
                    .and_then(move |body| Ok((status, body)))
                    .map_err(|e| Error::from(e.context(ErrorKind::Response(RequestType::GetModule))))
            })
            .and_then(|(status, body)| {
                if status.is_success() {
                    Ok(body)
                } else {
                    Err(Error::from(ErrorKind::Response(RequestType::GetModule)))
                    //Err(Error::from((status, &*body)))
                }
            })
            .and_then(|body| {
                let parsed: Result<aziot_identity_common::Identity, _> =
                    serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e.context(ErrorKind::JsonParse(RequestType::GetModule))))
            })
        )
    }

    pub fn get_modules(
        &self,
        _api_version: &str,
    ) -> Box<dyn Future<Item = Vec<aziot_identity_common::Identity>, Error = Error> + Send> 
    {
        let method = hyper::Method::POST;
        
        let uri = format!("{}identities/modules", self.host.as_str());

        let mut builder = hyper::Request::builder();
        builder.method(method).uri(uri);
        
        let req = builder
            .body(hyper::Body::empty())
            .expect("could not build hyper::Request");
        
        Box::new(
            self
            .client
            .request(req)
            .map_err(|e| Error::from(e.context(ErrorKind::Request(RequestType::ListModules))))
            .and_then(|resp| {
                let (http::response::Parts { status, .. }, body) = resp.into_parts();
                body.concat2()
                    .and_then(move |body| Ok((status, body)))
                    .map_err(|e| Error::from(e.context(ErrorKind::Response(RequestType::ListModules))))
            })
            .and_then(|(status, body)| {
                if status.is_success() {
                    Ok(body)
                } else {
                    Err(Error::from(ErrorKind::Response(RequestType::ListModules)))
                    //Err(Error::from((status, &*body)))
                }
            })
            .and_then(|body| {
                let parsed: Result<Vec<aziot_identity_common::Identity>, _> =
                    serde_json::from_slice(&body);
                parsed.map_err(|e| Error::from(e.context(ErrorKind::JsonParse(RequestType::ListModules))))
            })
        )
    }
}