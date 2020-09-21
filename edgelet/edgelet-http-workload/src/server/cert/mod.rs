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

fn cert_to_response<T: CoreCertificate>(cert: &T, context: ErrorKind) -> Result<CertificateResponse> {
    let cert_buffer = match cert.pem() {
        Ok(cert_buffer) => cert_buffer,
        Err(err) => return Err(Error::from(err.context(context))),
    };

    let expiration = match cert.get_valid_to() {
        Ok(expiration) => expiration,
        Err(err) => return Err(Error::from(err.context(context))),
    };

    let private_key = match cert.get_private_key() {
        Ok(Some(CorePrivateKey::Ref(ref_))) => {
            PrivateKeyResponse::new("ref".to_string()).with_ref(ref_)
        }
        Ok(Some(CorePrivateKey::Key(KeyBytes::Pem(buffer)))) => {
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
    cert_client: &Arc<Mutex<CertificateClient>>,
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

    cert_client
        .lock()
        .expect("certificate client lock error")
        .create_cert(&alias, &csr, None)
        .map_err(|err| Err(Error::from(err.context(context))))
        .map(|cert| -> Result<_> { 
            let pk = privkey.private_key_to_pem_pkcs8().context(context)?;
            let cert = Certificate::new(cert, pk);
            let cert = cert_to_response(&cert, context.clone())?;
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
         })
}


#[derive(Debug)]
pub struct Certificate
{
    pem: Vec<u8>,
    private_key: Vec<u8>,
}

impl Certificate {
    pub fn new(pem: Vec<u8>, private_key: Vec<u8>) -> Certificate {
        Certificate { pem, private_key }
    }
}

impl CoreCertificate for Certificate {
    type Buffer = Vec<u8>;
    type KeyBuffer = Vec<u8>;

    fn pem(&self) -> std::result::Result<Self::Buffer, edgelet_core::Error> {
        Ok(self.pem)
    }

    fn get_private_key(&self) -> std::result::Result<Option<CorePrivateKey<Self::KeyBuffer>>, edgelet_core::Error> {
        Ok(Some(CorePrivateKey::Key(KeyBytes::Pem(self.private_key))))
    }

    fn get_valid_to(&self) -> std::result::Result<DateTime<Utc>, edgelet_core::Error> {
        fn parse_openssl_time(
            time: &openssl::asn1::Asn1TimeRef,
        ) -> chrono::ParseResult<chrono::DateTime<chrono::Utc>> {
            // openssl::asn1::Asn1TimeRef does not expose any way to convert the ASN1_TIME to a Rust-friendly type
            //
            // Its Display impl uses ASN1_TIME_print, so we convert it into a String and parse it back
            // into a chrono::DateTime<chrono::Utc>
            let time = time.to_string();
            let time = chrono::NaiveDateTime::parse_from_str(&time, "%b %e %H:%M:%S %Y GMT")?;
            Ok(chrono::DateTime::<chrono::Utc>::from_utc(time, chrono::Utc))
        }
        
        let cert = openssl::x509::X509::from_pem(&self.pem).map_err(|e| edgelet_core::Error::from(edgelet_core::ErrorKind::CertificateCreate))?;
        let not_after = parse_openssl_time(cert.not_after()).map_err(|e| edgelet_core::Error::from(edgelet_core::ErrorKind::ParseSince))?;
        Ok(not_after)
    }

    fn get_common_name(&self) -> std::result::Result<String, edgelet_core::Error> {
        unimplemented!()
    }
}
