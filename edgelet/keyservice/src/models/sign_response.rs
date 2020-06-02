/*
 * Key Service API
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * OpenAPI spec version: 2020-06-01
 *
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    /// Signature of the data.
    #[serde(rename = "signature")]
    signature: String,
}

impl SignResponse {
    pub fn new(signature: String) -> SignResponse {
        SignResponse { signature }
    }

    pub fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }

    pub fn with_signature(mut self, signature: String) -> SignResponse {
        self.signature = signature;
        self
    }

    pub fn signature(&self) -> &String {
        &self.signature
    }
}
