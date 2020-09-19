// Copyright (c) Microsoft. All rights reserved.

use std::cmp;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use failure::{Fail, ResultExt};
use futures::future::Future;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Body, Response, StatusCode};

use cert_client::client::CertificateClient;
use edgelet_core::{Certificate as CoreCertificate, CertificateProperties, KeyBytes, PrivateKey as CorePrivateKey};
use edgelet_utils::ensure_not_empty_with_context;
use workload::models::{CertificateResponse, PrivateKey as PrivateKeyResponse};

use crate::error::{Error, ErrorKind, Result};

mod identity;
mod server;

pub use self::identity::IdentityCertHandler;
pub use self::server::ServerCertHandler;

fn cert_to_response<T: Certificate>(cert: &T, context: ErrorKind) -> Result<CertificateResponse> {
    let cert_buffer = match cert.pem() {
        Ok(cert_buffer) => cert_buffer,
        Err(err) => return Err(Error::from(err.context(context))),
    };

    let expiration = match cert.get_valid_to() {
        Ok(expiration) => expiration,
        Err(err) => return Err(Error::from(err.context(context))),
    };

    let private_key = match cert.get_private_key() {
        Ok(Some(PrivateKey::Ref(ref_))) => {
            PrivateKeyResponse::new("ref".to_string()).with_ref(ref_)
        }
        Ok(Some(PrivateKey::Key(KeyBytes::Pem(buffer)))) => {
            PrivateKeyResponse::new("key".to_string())
                .with_bytes(String::from_utf8_lossy(buffer.as_ref()).to_string())
        }
        Ok(None) => return Err(ErrorKind::BadPrivateKey.into()),
        Err(err) => return Err(Error::from(err.context(context))),
    };

    Ok(CertificateResponse::new(
        private_key,
        String::from_utf8_lossy(cert_buffer.as_ref()).to_string(),
        expiration.to_rfc3339(),
    ))
}

fn compute_validity(expiration: &str, max_duration_sec: i64, context: ErrorKind) -> Result<i64> {
    ensure_not_empty_with_context(expiration, || context.clone())?;

    let expiration = DateTime::parse_from_rfc3339(expiration).context(context)?;

    let secs = expiration
        .with_timezone(&Utc)
        .signed_duration_since(Utc::now())
        .num_seconds();

    Ok(cmp::min(secs, max_duration_sec))
}

fn refresh_cert(
    cert_client: Arc<Mutex<CertificateClient>>,
    alias: String,
    props: &CertificateProperties,
    context: ErrorKind,
) -> Result<Response<Body>> {
    // if let Err(err) = hsm.destroy_certificate(alias) {
    //     return Err(Error::from(err.context(context)));
    // };

    // let cert = match hsm.create_certificate(props) {
    //     Ok(cert) => cert,
    //     Err(err) => return Err(Error::from(err.context(context))),
    // };

    let rsa = openssl::rsa::Rsa::generate(2048)
        .context(context)?;
    let privkey = openssl::pkey::PKey::from_rsa(rsa)
        .context(context)?;
    
    let mut csr = openssl::x509::X509Req::builder()
        .context(context)?;
    
    csr.set_version(0).context(context)?;

    let mut subject_name = 
        openssl::x509::X509Name::builder()
        .context(context)?;
    subject_name.append_entry_by_text("CN", props.common_name());
    let subject_name = subject_name.build();
    csr.set_subject_name(&subject_name).context(context)?;

    let client_extension =
        openssl::x509::extension::ExtendedKeyUsage::new().server_auth().build()
        .context(context)?;
    let mut extensions =
        openssl::stack::Stack::new()
        .context(context)?;
    extensions
        .push(client_extension)
        .context(context)?;
    
    if !props.san_entries().is_none() {
        let subject_alt_name = openssl::x509::extension::SubjectAlternativeName::new();
        let result = props
            .san_entries()
            .expect("san entries unexpectedly empty")
            .iter()
            .map(|s| subject_alt_name.dns(s))
            .collect();
        let san = subject_alt_name
            .build(&csr.x509v3_context(None))
            .context(context)?;
        extensions.push(san).context(context)?;
    }

    csr
        .add_extensions(&extensions)
        .context(context)?;

    csr
        .sign(&privkey, openssl::hash::MessageDigest::sha256())
        .context(context)?;

    let csr = csr.build();
    let csr = csr.to_pem()
        .context(context)?;

    let cert = cert_client
        .lock()
        .expect("certificate client lock error")
        .create_cert(&alias, &csr, None)
        .map_err(|err| Err(Error::from(err.context(context))))
        .map(|cert| { 
            
            let cert = cert_to_response(&cert, context.clone())?;
            
         })


    let body = match serde_json::to_string(&cert) {
        Ok(body) => body,
        Err(err) => return Err(Error::from(err.context(context))),
    };

    let response = Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, body.len().to_string().as_str())
        .body(body.into())
        .context(context)?;

    Ok(response)
}


#[derive(Debug)]
pub struct Certificate
{}

impl Certificate {
    pub fn new() -> Certificate {
        Certificate {}
    }
}

impl CoreCertificate for Certificate {
    type Buffer = String;
    type KeyBuffer = Vec<u8>;

    fn pem(&self) -> Result<Self::Buffer> {
        self.0
            .pem()
            .map_err(|err| Error::from(err.context(ErrorKind::Hsm)))
    }

    fn get_private_key(&self) -> Result<Option<CorePrivateKey<Self::KeyBuffer>>> {
        self.0
            .get_private_key()
            .map(|pk| match pk {
                Some(HsmPrivateKey::Key(HsmKeyBytes::Pem(key_buffer))) => {
                    Some(CorePrivateKey::Key(CoreKeyBytes::Pem(key_buffer)))
                }
                Some(HsmPrivateKey::Ref(key_string)) => Some(CorePrivateKey::Ref(key_string)),
                None => None,
            })
            .map_err(|err| Error::from(err.context(ErrorKind::Hsm)))
    }

    fn get_valid_to(&self) -> Result<DateTime<Utc>> {
        self.0
            .get_valid_to()
            .map_err(|err| Error::from(err.context(ErrorKind::Hsm)))
    }

    fn get_common_name(&self) -> Result<String> {
        self.0
            .get_common_name()
            .map_err(|err| Error::from(err.context(ErrorKind::Hsm)))
    }
}
