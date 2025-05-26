use base64::Engine;
use hyper::{Body, HeaderMap, Request, Response, StatusCode};
use std::{
    error::Error,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

#[derive(Debug, Clone)]
pub(crate) struct BasicAuthLayer {
    token: String,
}

impl BasicAuthLayer {
    pub fn new(token: String) -> Self {
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
    token: Arc<str>,
}

impl<S> BasicAuth<S> {
    pub fn new(inner: S, token: String) -> Self {
        Self {
            inner,
            token: Arc::from(token.as_str()),
        }
    }

    fn check_auth(&self, headers: &HeaderMap) -> bool {
        headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Basic "))
            .map_or(false, |token| token == self.token.as_ref())
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
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

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
        let res_fut = async move { fut.await.map_err(|err| err.into()) };
        Box::pin(res_fut)
    }
}

pub fn auth_cookie(user: &str, password: &str) -> String {
    format!("{user}:{password}")
}

pub fn auth_token_from_cookie(cookie: &str) -> String {
    base64::prelude::BASE64_STANDARD.encode(cookie)
}

pub fn auth_token_from_creds(user: &str, password: &str) -> String {
    base64::prelude::BASE64_STANDARD.encode(auth_cookie(user, password))
}
