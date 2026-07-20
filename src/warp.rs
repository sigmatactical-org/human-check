//! Warp glue for the human-check challenge endpoint.

use std::convert::Infallible;

use warp::http::StatusCode;
use warp::{Filter, Rejection, Reply};

use crate::HumanCheck;

/// `GET /human-check/challenge` — fresh signed PoW challenge (JSON).
pub fn routes(
    check: HumanCheck,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + 'static {
    warp::path!("human-check" / "challenge")
        .and(warp::path::end())
        .and(warp::get())
        .and(with_check(check))
        .and_then(|check: HumanCheck| async move {
            if !check.is_enabled() {
                return Ok(
                    warp::reply::with_status("disabled", StatusCode::NOT_FOUND).into_response()
                );
            }
            let response: warp::reply::Response = match check.issue_challenge() {
                Ok(challenge) => match serde_json::to_string(&challenge) {
                    Ok(body) => warp::reply::with_header(
                        warp::reply::Response::new(body.into()),
                        "content-type",
                        "application/json",
                    )
                    .into_response(),
                    Err(_) => warp::reply::with_status(
                        "challenge unavailable",
                        StatusCode::INTERNAL_SERVER_ERROR,
                    )
                    .into_response(),
                },
                Err(_) => warp::reply::with_status(
                    "challenge unavailable",
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
                .into_response(),
            };
            Ok::<warp::reply::Response, Rejection>(response)
        })
}

/// Warp filter injecting the shared [`HumanCheck`] instance.
pub fn with_check(
    check: HumanCheck,
) -> impl Filter<Extract = (HumanCheck,), Error = Infallible> + Clone + Send + 'static {
    warp::any().map(move || check.clone())
}
