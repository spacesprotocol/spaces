use std::{
    error::Error,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use base64::Engine;
use hyper::{Body, Request, Response, StatusCode, HeaderMap};
use tower::{Layer, Service};

#[derive(Debug, Clone)]
pub(crate) struct BasicAuthLayer {
    token: Option<String>,
}

impl BasicAuthLayer {
    pub fn new(token: Option<String>) -> Self {
        Self { token }
    }
}

impl<S> Layer<S> for BasicAuthLayer {
    type Service = BasicAuth<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BasicAuth::new(inner, self.token.clone())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BasicAuth<S> {
    inner: S,
    token: Option<Arc<str>>,
}

impl<S> BasicAuth<S> {
    pub fn new(inner: S, token: Option<String>) -> Self {
        Self {
            inner,
            token: token.map(|t| Arc::from(t.as_str())),
        }
    }

    fn check_auth(&self, headers: &HeaderMap) -> bool {
        let Some(expected_token) = &self.token else {
            return true;
        };

        let auth_header = match headers.get("authorization") {
            Some(header) => header,
            None => return false,
        };

        let auth_str = match auth_header.to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };

        if let Some(token_part) = auth_str.strip_prefix("Basic ") {
            token_part == expected_token.as_ref()
        } else {
            false
        }
    }

    fn unauthorized_response() -> Response<Body> {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"Protected\"")
            .body(Body::from("Unauthorized"))
            .expect("Failed to build unauthorized response")
    }
}

impl<S> Service<Request<Body>> for BasicAuth<S>
where
    S: Service<Request<Body>, Response = Response<Body>>,
    S::Response: 'static,
    S::Error: Into<Box<dyn Error + Send + Sync>> + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = Box<dyn Error + Send + Sync + 'static>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        if !self.check_auth(req.headers()) {
            let response = Self::unauthorized_response();
            return Box::pin(async move { Ok(response) });
        }

        let fut = self.inner.call(req);
        let res_fut = async move {
            fut.await.map_err(|err| err.into())
        };
        Box::pin(res_fut)
    }
}

pub fn basic_auth_token(user: &str, password: &str) -> String {
    base64::prelude::BASE64_STANDARD.encode(format!("{user}:{password}"))
}