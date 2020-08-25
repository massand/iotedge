// Copyright (c) Microsoft. All rights reserved.

use std::fmt;
use std::fmt::Display;

use failure::{Backtrace, Context, Fail};

#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

#[derive(Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "Invalid URI to parse: {:?}", _0)]
    Uri(url::ParseError),

    #[fail(display = "Invalid HTTP header value {:?}", _0)]
    HeaderValue(String),

    #[fail(display = "Hyper HTTP error")]
    Hyper,

    #[fail(display = "HTTP request error: {}", _0)]
    Request(RequestType),

    #[fail(display = "HTTP response error: {}", _0)]
    Response(RequestType),

    #[fail(display = "HTTP response error: {}", _0)]
    JsonParse(RequestType),

    // #[cfg(test)]
    // #[fail(display = "HTTP test error")]
    // HttpTest,
}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl Error {
    pub fn new(inner: Context<ErrorKind>) -> Self {
        Error { inner }
    }

    pub fn kind(&self) -> &ErrorKind {
        self.inner.get_context()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Self {
        Error { inner }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum RequestType {
    GetDevice,
}

impl Display for RequestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
