use actix_cors::Cors;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, get, web};
use std::env;
use std::sync::{Mutex, OnceLock};

static REDEEM_REGISTRY: OnceLock<Mutex<Vec<(String, String)>>> = OnceLock::new();

fn redeem_registry() -> &'static Mutex<Vec<(String, String)>> {
    REDEEM_REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn redeem_register(key: String, value: String) {
    redeem_registry().lock().unwrap().push((key, value));
}

fn redeem_take(key: &str) -> Option<String> {
    let mut entries = redeem_registry().lock().unwrap();
    let pos = entries.iter().position(|(entry, _)| entry == key)?;
    Some(entries.remove(pos).1)
}

static HCA_TOKEN_REGISTRY: OnceLock<Mutex<Vec<(String, String)>>> = OnceLock::new();

fn hca_token_registry() -> &'static Mutex<Vec<(String, String)>> {
    HCA_TOKEN_REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn hca_token_register(key: String, value: String) {
    hca_token_registry().lock().unwrap().push((key, value));
}

fn hca_token_take(key: &str) -> Option<String> {
    let mut entries = hca_token_registry().lock().unwrap();
    let pos = entries.iter().position(|(entry, _)| entry == key)?;
    Some(entries.remove(pos).1)
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("resources/index.html"))
}

#[get("/button")]
async fn button(req: HttpRequest) -> impl Responder {
    let conn = req.connection_info();
    let page = include_str!("resources/button.html")
        .replace(
            "{CLIENT_ID}",
            &env::var("HCA_CLIENT_ID").unwrap_or_default(),
        )
        .replace("{SCHEMA}", conn.scheme())
        .replace("{BASE_URL}", conn.host());
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(page)
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(serde::Deserialize)]
struct CallbackArgs {
    code: String,
    state: String,
}

#[get("/callback")]
async fn callback(req: HttpRequest, query: web::Query<CallbackArgs>) -> impl Responder {
    let split_vec = query.state.split("fillout_url").collect::<Vec<&str>>();
    let crypto = split_vec[0];
    let fillout_url = split_vec[1];

    let redirect_uri = {
        let conn = req.connection_info();
        format!("{}://{}/callback", conn.scheme(), conn.host())
    };
    let client_id = env::var("HCA_CLIENT_ID").unwrap_or_default();
    let client_secret = env::var("HCA_CLIENT_SECRET").unwrap_or_default();

    let response = reqwest::Client::new()
        .post("https://auth.hackclub.com/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", query.code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
        ])
        .send()
        .await;

    let token = match response {
        Ok(response) => match response.json::<TokenResponse>().await {
            Ok(body) => body.access_token,
            Err(_) => return HttpResponse::BadGateway().finish(),
        },
        Err(_) => return HttpResponse::BadGateway().finish(),
    };

    redeem_register(crypto.to_string(), token);

    HttpResponse::SeeOther()
        .append_header(("Location", fillout_url))
        .finish()
}

#[derive(serde::Deserialize)]
struct RedeemArgs {
    state: String,
}

#[get("/redeem")]
async fn redeem(query: web::Query<RedeemArgs>) -> impl Responder {
    let token = match redeem_take(query.state.as_str()) {
        Some(token) => token,
        None => return HttpResponse::BadRequest().finish(),
    };
    HttpResponse::Ok().body(token)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allowed_header("ngrok-skip-browser-warning");

        App::new()
            .wrap(cors)
            .service(index)
            .service(button)
            .service(callback)
            .service(redeem)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
