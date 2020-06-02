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
pub struct ErrorResponse {
    #[serde(rename = "message")]
    message: String,
}

impl ErrorResponse {
    pub fn new(message: String) -> ErrorResponse {
        ErrorResponse { message }
    }

    pub fn set_message(&mut self, message: String) {
        self.message = message;
    }

    pub fn with_message(mut self, message: String) -> ErrorResponse {
        self.message = message;
        self
    }

    pub fn message(&self) -> &String {
        &self.message
    }
}
