// Vigil
//
// Microservices Status Page
// Copyright: 2021, Valerian Saliou <valerian@valeriansaliou.name>
// License: Mozilla Public License v2.0 (MPL v2.0)

use actix_web::{
  body::{EitherBody, MessageBody},
  dev::{Service, ServiceRequest, ServiceResponse, Transform},
  middleware::{self, Condition, TrailingSlash},
  rt, web, App, Error as ActixError, HttpServer,
};
use actix_web_httpauth::{
  extractors::{
    basic::{BasicAuth, Config as ConfigAuth},
    AuthenticationError,
  },
  middleware::HttpAuthentication,
};
use tera::Tera;

use super::routes;
use crate::APP_CONF;

pub fn run() {
  let runtime = rt::System::new();

  // Prepare templating engine
  let templates: String = APP_CONF
    .assets
    .path
    .canonicalize()
    .unwrap()
    .join("templates")
    .join("*")
    .to_str()
    .unwrap()
    .into();

  let tera = Tera::new(&templates).unwrap();

  // Prepare authentication middlewares
  let (middleware_reporter_auth, middleware_manager_auth) = (
    HttpAuthentication::basic(authenticate_reporter),
    HttpAuthentication::basic(authenticate_manager),
  );

  // Start the HTTP server
  let server = HttpServer::new(move || {
    App::new()
      .app_data(web::Data::new(tera.clone()))
      .app_data(ConfigAuth::default().realm(&APP_CONF.branding.page_title))
      .wrap(middleware::NormalizePath::new(TrailingSlash::Trim))
      .service(routes::assets_javascripts)
      .service(routes::assets_stylesheets)
      .service(routes::assets_images)
      .service(routes::assets_fonts)
      .service(routes::badge)
      .service(routes::robots)
      .service(routes::status_text)
      .service(routes::index)
      .service(
        web::scope("/reporter")
          .wrap(middleware_reporter_auth.clone())
          .service(web::resource("/{probe_id}/{node_id}").post(routes::reporter_report))
          .service(
            web::resource("/{probe_id}/{node_id}/{replica_id}").delete(routes::reporter_flush),
          ),
      )
      .service(
        web::scope("/manager")
          .wrap(middleware_manager_auth.clone())
          .service(web::resource("/announcements").get(routes::manager_announcements))
          .service(web::resource("/announcement").post(routes::manager_announcement_insert))
          .service(
            web::resource("/announcement/{announcement_id}")
              .delete(routes::manager_announcement_retract),
          )
          .service(web::resource("/prober/alerts").get(routes::manager_prober_alerts))
          .service(
            web::resource("/prober/alerts/ignored")
              .get(routes::manager_prober_alerts_ignored_resolve),
          )
          .service(
            web::resource("/prober/alerts/ignored")
              .put(routes::manager_prober_alerts_ignored_update),
          ),
      )
  })
  .workers(APP_CONF.server.workers)
  .bind(APP_CONF.server.inet)
  .unwrap()
  .run();

  runtime.block_on(server).unwrap()
}

fn authenticate(
  request: ServiceRequest,
  credentials: BasicAuth,
  token: &str,
  username: Option<&str>,
) -> Result<ServiceRequest, (ActixError, ServiceRequest)> {
  let password = credentials.password().unwrap_or("");

  let username_valid = match username {
    None => true,
    Some(username) => username == credentials.user_id(),
  };

  if password == token && username_valid {
    Ok(request)
  } else {
    let mut error = AuthenticationError::from(
      request
        .app_data::<ConfigAuth>()
        .cloned()
        .unwrap_or_else(ConfigAuth::default),
    );

    *error.status_code_mut() = actix_web::http::StatusCode::FORBIDDEN;

    Err((error.into(), request))
  }
}

async fn authenticate_reporter(
  request: ServiceRequest,
  credentials: BasicAuth,
) -> Result<ServiceRequest, (ActixError, ServiceRequest)> {
  authenticate(request, credentials, &APP_CONF.server.reporter_token, None)
}

async fn authenticate_manager(
  request: ServiceRequest,
  credentials: BasicAuth,
) -> Result<ServiceRequest, (ActixError, ServiceRequest)> {
  authenticate(request, credentials, &APP_CONF.server.manager_token, None)
}

async fn authenticate_ui(
  request: ServiceRequest,
  credentials: BasicAuth,
) -> Result<ServiceRequest, (ActixError, ServiceRequest)> {
  if !APP_CONF.server.ui_auth_enabled {
    return Ok(request);
  }

  let username = &APP_CONF.server.ui_username;
  let password = &APP_CONF.server.ui_password;
  authenticate(request, credentials, password, Some(username))
}

// This type is very complicated, but unfortunately typing this directly
// requires https://github.com/rust-lang/rust/issues/99697 to be merged.
// The issue is that we can't specify the second generic argument of
// HttpAuthentication<T, F>, because it look something like this:
// ```
// impl Fn(ServiceRequest, BearerAuth) -> impl Future<
//    Output = Result<ServiceRequest, (actix_web::Error, ServiceRequest)>,
//  >
// ``
// which isn't valid (until the linked issue is merged).
pub fn ui_auth<B, S>() -> impl Transform<
  S,
  ServiceRequest,
  Response = ServiceResponse<EitherBody<EitherBody<B>, B>>,
  Error = ActixError,
  InitError = (),
>
where
  B: MessageBody + 'static,
  S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
{
  let enabled = APP_CONF.server.ui_auth_enabled;
  Condition::new(enabled, HttpAuthentication::basic(authenticate_ui))
}
