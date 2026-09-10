use actix_cors::Cors;
use actix_web::http::header;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, get, web};
use rand::RngExt;
use rand::distr::Alphanumeric;
use std::env;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const REGISTRY_TTL: Duration = Duration::from_secs(600);

static REDEEM_REGISTRY: OnceLock<Mutex<Vec<(String, String, Instant)>>> = OnceLock::new();

fn redeem_registry() -> MutexGuard<'static, Vec<(String, String, Instant)>> {
    let mut entries = REDEEM_REGISTRY
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap();
    entries.retain(|(_, _, created)| created.elapsed() < REGISTRY_TTL);
    entries
}

fn redeem_register(key: String, value: String) {
    redeem_registry().push((key, value, Instant::now()));
}

fn redeem_take(key: &str) -> Option<String> {
    let mut entries = redeem_registry();
    let pos = entries.iter().position(|(entry, _, _)| entry == key)?;
    Some(entries.remove(pos).1)
}

static HCA_TOKEN_REGISTRY: OnceLock<Mutex<Vec<(String, String, Instant)>>> = OnceLock::new();

fn hca_token_registry() -> MutexGuard<'static, Vec<(String, String, Instant)>> {
    let mut entries = HCA_TOKEN_REGISTRY
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap();
    entries.retain(|(_, _, created)| created.elapsed() < REGISTRY_TTL);
    entries
}

fn hca_token_register(key: String, value: String) {
    hca_token_registry().push((key, value, Instant::now()));
}

fn hca_token_take(key: &str) -> Option<String> {
    let mut entries = hca_token_registry();
    let pos = entries.iter().position(|(entry, _, _)| entry == key)?;
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
    let hca_token = match redeem_take(query.state.as_str()) {
        Some(token) => token,
        None => return HttpResponse::BadRequest().finish(),
    };
    let opaque_token: String = (&mut rand::rng())
        .sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    hca_token_register(opaque_token.clone(), hca_token);

    HttpResponse::Ok().body(opaque_token)
}

#[derive(serde::Serialize, Default)]
struct Fields {
    first_name: String,
    last_name: String,
    email: String,
    address_line_1: String,
    address_line_2: String,
    city: String,
    state: String,
    country: String,
    postal_code: String,
    birthday: String,
    phone: String,
    ysws_eligible: bool,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct AuthData {
    identity: Identity,
    scopes: Vec<String>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Identity {
    id: String,
    first_name: Option<String>,
    last_name: Option<String>,
    primary_email: Option<String>,
    verification_status: Option<String>,
    ysws_eligible: Option<bool>,
    slack_id: Option<String>,
    phone_number: Option<String>,
    birthday: Option<String>,
    addresses: Option<Vec<Address>>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Address {
    id: String,
    first_name: Option<String>,
    last_name: Option<String>,
    line_1: String,
    line_2: Option<String>,
    city: String,
    state: String,
    postal_code: String,
    country: String,
    phone_number: Option<String>,
    primary: bool,
}

#[get("/fields")]
async fn fields(req: HttpRequest) -> impl Responder {
    let opaque_token = match req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    {
        Some(token) => token,
        None => return HttpResponse::Unauthorized().finish(),
    };
    let hca_token = match hca_token_take(opaque_token) {
        Some(token) => token,
        None => return HttpResponse::Unauthorized().finish(),
    };

    let response = reqwest::Client::new()
        .get("https://auth.hackclub.com/api/v1/me")
        .bearer_auth(hca_token)
        .send()
        .await;

    let auth_data = match response {
        Ok(response) => match response.json::<AuthData>().await {
            Ok(auth_data) => auth_data,
            Err(_) => return HttpResponse::BadGateway().finish(),
        },
        Err(_) => return HttpResponse::BadGateway().finish(),
    };

    let addresses = auth_data.identity.addresses.unwrap_or_default();
    let primary_address = addresses
        .iter()
        .find(|address| address.primary)
        .or_else(|| addresses.first());

    HttpResponse::Ok().json(Fields {
        first_name: auth_data.identity.first_name.unwrap_or_default(),
        last_name: auth_data.identity.last_name.unwrap_or_default(),
        email: auth_data.identity.primary_email.unwrap_or_default(),
        address_line_1: primary_address
            .map(|address| address.line_1.clone())
            .unwrap_or_default(),
        address_line_2: primary_address
            .and_then(|address| address.line_2.clone())
            .unwrap_or_default(),
        city: primary_address
            .map(|address| address.city.clone())
            .unwrap_or_default(),
        state: primary_address
            .map(|address| address.state.clone())
            .unwrap_or_default(),
        country: primary_address
            .map(|address| address.country.clone())
            .unwrap_or_default(),
        postal_code: primary_address
            .map(|address| address.postal_code.clone())
            .unwrap_or_default(),
        birthday: auth_data.identity.birthday.unwrap_or_default(),
        phone: auth_data.identity.phone_number.unwrap_or_default(),
        ysws_eligible: auth_data.identity.ysws_eligible.unwrap_or_default(),
    })
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
            .service(fields)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
