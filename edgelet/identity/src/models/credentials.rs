/* 
 * Identity Service API
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * OpenAPI spec version: 2020-02-02
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */


#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct Credentials {
  /// Indicates the type of authentication credential used.
  #[serde(rename = "authType")]
  auth_type: String,
  /// The symmetric key used for authentication. Specified only if the 'authType' is 'symmetric-key'.
  #[serde(rename = "key", skip_serializing_if="Option::is_none")]
  key: Option<String>,
  /// The identity certificate. Should be a PEM formatted byte array if the 'authType' is 'x509'.
  #[serde(rename = "identityCert", skip_serializing_if="Option::is_none")]
  identity_cert: Option<String>
}

impl Credentials {
  pub fn new(auth_type: String) -> Credentials {
    Credentials {
      auth_type: auth_type,
      key: None,
      identity_cert: None
    }
  }

  pub fn set_auth_type(&mut self, auth_type: String) {
    self.auth_type = auth_type;
  }

  pub fn with_auth_type(mut self, auth_type: String) -> Credentials {
    self.auth_type = auth_type;
    self
  }

  pub fn auth_type(&self) -> &String {
    &self.auth_type
  }


  pub fn set_key(&mut self, key: String) {
    self.key = Some(key);
  }

  pub fn with_key(mut self, key: String) -> Credentials {
    self.key = Some(key);
    self
  }

  pub fn key(&self) -> Option<&String> {
    self.key.as_ref()
  }

  pub fn reset_key(&mut self) {
    self.key = None;
  }

  pub fn set_identity_cert(&mut self, identity_cert: String) {
    self.identity_cert = Some(identity_cert);
  }

  pub fn with_identity_cert(mut self, identity_cert: String) -> Credentials {
    self.identity_cert = Some(identity_cert);
    self
  }

  pub fn identity_cert(&self) -> Option<&String> {
    self.identity_cert.as_ref()
  }

  pub fn reset_identity_cert(&mut self) {
    self.identity_cert = None;
  }

}



