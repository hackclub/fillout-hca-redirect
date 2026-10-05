use actix_cors::Cors;
use actix_governor::{Governor, GovernorConfigBuilder, KeyExtractor, SimpleKeyExtractionError};
use actix_web::dev::ServiceRequest;
use std::net::IpAddr;
use actix_web::http::header;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, get, web};
use rand::RngExt;
use rand::distr::Alphanumeric;
use std::env;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const REGISTRY_TTL: Duration = Duration::from_secs(600);
const STATE_SEPARATOR: &str = "hack_club-redirect_fillout_url";
const REDEEM_FRAGMENT: &str = "hca_redeem";

#[cfg(debug_assertions)]
const NGROK_HEADER: &str = "\"ngrok-skip-browser-warning\": \"1\",";
#[cfg(not(debug_assertions))]
const NGROK_HEADER: &str = "";

struct Config {
    base_url: String,
    client_id: String,
    client_secret: String,
}

static CONFIG: OnceLock<Config> = OnceLock::new();

fn config() -> &'static Config {
    CONFIG.get().expect("config is set before the server starts")
}

fn require_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

#[cfg(not(debug_assertions))]
const BASE_URL: &str = "https://fillout-hca-redirect.hackclub.com";

#[cfg(debug_assertions)]
fn base_url() -> String {
    require_env("BASE_URL")
}

#[cfg(not(debug_assertions))]
fn base_url() -> String {
    BASE_URL.to_string()
}

fn random_token() -> String {
    (&mut rand::rng())
        .sample_iter(Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

const ALLOWED_FORM_HOSTS: [&str; 2] = ["fillout.com", "forms.hackclub.com"];

fn is_allowed_form_url(url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    if url.scheme() != "https" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    ALLOWED_FORM_HOSTS
        .iter()
        .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
}

#[cfg(not(debug_assertions))]
fn is_allowed_origin(origin: &header::HeaderValue) -> bool {
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    origin == config().base_url || is_allowed_form_url(origin)
}

fn is_trusted_proxy(peer: &IpAddr) -> bool {
    match peer {
        IpAddr::V4(peer) => peer.is_loopback() || peer.is_private() || peer.is_link_local(),
        IpAddr::V6(peer) => {
            let segments = peer.segments();
            peer.is_loopback()
                || segments[0] & 0xfe00 == 0xfc00
                || segments[0] & 0xffc0 == 0xfe80
        }
    }
}

#[derive(Clone)]
struct ClientIpKeyExtractor;

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = String;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        let peer = req.peer_addr().map(|socket| socket.ip());
        let forwarded = peer
            .filter(is_trusted_proxy)
            .and(req.headers().get("x-forwarded-for"))
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(|client| client.trim().to_string());

        forwarded
            .or_else(|| peer.map(|peer| peer.to_string()))
            .ok_or_else(|| SimpleKeyExtractionError::new("could not determine client address"))
    }
}

static REDEEM_REGISTRY: OnceLock<Mutex<Vec<(String, String, String, Instant)>>> = OnceLock::new();

fn redeem_registry() -> MutexGuard<'static, Vec<(String, String, String, Instant)>> {
    let mut entries = REDEEM_REGISTRY
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap();
    entries.retain(|(_, _, _, created)| created.elapsed() < REGISTRY_TTL);
    entries
}

fn redeem_register(key: String, nonce: String, value: String) {
    let mut entries = redeem_registry();
    entries.retain(|(entry, _, _, _)| entry != &key);
    entries.push((key, nonce, value, Instant::now()));
}

fn redeem_take(key: &str, nonce: &str) -> Option<String> {
    let mut entries = redeem_registry();
    let pos = entries.iter().position(|(entry, _, _, _)| entry == key)?;
    if entries[pos].1 != nonce {
        return None;
    }
    Some(entries.remove(pos).2)
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
    let mut entries = hca_token_registry();
    entries.retain(|(entry, _, _)| entry != &key);
    entries.push((key, value, Instant::now()));
}

fn hca_token_get(key: &str) -> Option<String> {
    hca_token_registry()
        .iter()
        .find(|(entry, _, _)| entry == key)
        .map(|(_, value, _)| value.clone())
}

fn hca_token_take(key: &str) -> Option<String> {
    let mut entries = hca_token_registry();
    let pos = entries.iter().position(|(entry, _, _)| entry == key)?;
    Some(entries.remove(pos).1)
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body("Hack Club Fillout HCA Redirect")
}

#[get("/button")]
async fn button() -> impl Responder {
    let page = include_str!("resources/button.html")
        .replace("{CLIENT_ID}", &config().client_id)
        .replace("{BASE_URL}", &config().base_url)
        .replace("{NGROK_HEADER}", NGROK_HEADER);
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
async fn callback(query: web::Query<CallbackArgs>) -> impl Responder {
    let Some((nonce, fillout_url)) = query.state.split_once(STATE_SEPARATOR) else {
        return HttpResponse::BadRequest().body("malformed state");
    };
    if nonce.is_empty() || nonce.len() > 128 {
        return HttpResponse::BadRequest().body("malformed state");
    }
    if !is_allowed_form_url(fillout_url) {
        return HttpResponse::BadRequest().body("redirect target not allowed");
    }

    let redirect_uri = format!("{}/callback", config().base_url);

    let response = match reqwest::Client::new()
        .post("https://auth.hackclub.com/oauth/token")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", query.code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", config().client_id.as_str()),
            ("client_secret", config().client_secret.as_str()),
        ])
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return HttpResponse::BadGateway().finish(),
    };

    let body = response.text().await.unwrap_or_default();

    let token = match serde_json::from_str::<TokenResponse>(&body) {
        Ok(body) => body.access_token,
        Err(_) => return HttpResponse::BadGateway().finish(),
    };

    let redeem_id = random_token();
    redeem_register(redeem_id.clone(), nonce.to_string(), token);

    let form_url = fillout_url.split('#').next().unwrap_or(fillout_url);

    HttpResponse::SeeOther()
        .append_header((
            "Location",
            format!("{form_url}#{REDEEM_FRAGMENT}={redeem_id}"),
        ))
        .finish()
}

#[derive(serde::Deserialize)]
struct RedeemArgs {
    redeem: String,
    nonce: String,
}

#[get("/redeem")]
async fn redeem(query: web::Query<RedeemArgs>) -> impl Responder {
    let Some(hca_token) = redeem_take(query.redeem.as_str(), query.nonce.as_str()) else {
        return HttpResponse::BadRequest().finish();
    };

    let opaque_token = random_token();
    hca_token_register(opaque_token.clone(), hca_token);

    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .body(opaque_token)
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
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Identity {
    id: Option<String>,
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
    id: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    line_1: Option<String>,
    line_2: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    phone_number: Option<String>,
    #[serde(default)]
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
        None => return HttpResponse::Unauthorized().body("missing bearer token"),
    };
    let hca_token = match hca_token_get(opaque_token) {
        Some(token) => token,
        None => return HttpResponse::Unauthorized().body("unknown or already used token"),
    };
    let response = match reqwest::Client::new()
        .get("https://auth.hackclub.com/api/v1/me")
        .bearer_auth(hca_token)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return HttpResponse::BadGateway().finish(),
    };

    let body = response.text().await.unwrap_or_default();

    let auth_data = match serde_json::from_str::<AuthData>(&body) {
        Ok(auth_data) => auth_data,
        Err(_) => return HttpResponse::BadGateway().finish(),
    };

    let _ = hca_token_take(opaque_token);

    let addresses = auth_data.identity.addresses.unwrap_or_default();
    let primary_address = addresses
        .iter()
        .find(|address| address.primary)
        .or_else(|| addresses.first());

    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .json(Fields {
        first_name: auth_data.identity.first_name.unwrap_or_default(),
        last_name: auth_data.identity.last_name.unwrap_or_default(),
        email: auth_data.identity.primary_email.unwrap_or_default(),
        address_line_1: primary_address
            .and_then(|address| address.line_1.clone())
            .unwrap_or_default(),
        address_line_2: primary_address
            .and_then(|address| address.line_2.clone())
            .unwrap_or_default(),
        city: primary_address
            .and_then(|address| address.city.clone())
            .unwrap_or_default(),
        state: primary_address
            .and_then(|address| address.state.clone())
            .unwrap_or_default(),
        country: primary_address
            .and_then(|address| address.country.clone())
            .unwrap_or_default(),
        postal_code: primary_address
            .and_then(|address| address.postal_code.clone())
            .unwrap_or_default(),
        birthday: auth_data.identity.birthday.unwrap_or_default(),
        phone: auth_data.identity.phone_number.unwrap_or_default(),
        ysws_eligible: auth_data.identity.ysws_eligible.unwrap_or_default(),
    })
}


#[get("/airtable")]
async fn airtable() -> impl Responder {
    let script = include_str!("resources/airtable.js")
        .replace("{BASE_URL}", &config().base_url)
        .replace("{NGROK_HEADER}", NGROK_HEADER);
    HttpResponse::Ok()
        .content_type("text/javascript; charset=utf-8")
        .body(script)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if CONFIG
        .set(Config {
            base_url: base_url(),
            client_id: require_env("HCA_CLIENT_ID"),
            client_secret: require_env("HCA_CLIENT_SECRET"),
        })
        .is_err()
    {
        panic!("config was already set");
    }

    let governor = GovernorConfigBuilder::default()
        .key_extractor(ClientIpKeyExtractor)
        .seconds_per_request(1)
        .burst_size(20)
        .finish()
        .expect("valid governor config");

    HttpServer::new(move || {
        let cors = Cors::default().allowed_methods(["GET"]);
        #[cfg(debug_assertions)]
        let cors = cors
            .allowed_origin_fn(|_, _| true)
            .allowed_header("ngrok-skip-browser-warning");
        #[cfg(not(debug_assertions))]
        let cors = cors.allowed_origin_fn(|origin, _| is_allowed_origin(origin));

        App::new()
            .wrap(cors)
            .wrap(Governor::new(&governor))
            .service(index)
            .service(button)
            .service(callback)
            .service(redeem)
            .service(fields)
            .service(airtable)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
