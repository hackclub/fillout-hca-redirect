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

const HCA_TOKEN_TTL: Duration = Duration::from_secs(3060);
const REDEEM_TTL: Duration = Duration::from_secs(600);
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

fn allowed_form_url(url: &str) -> Option<reqwest::Url> {
    let url = reqwest::Url::parse(url).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    let host = url.host_str()?;
    ALLOWED_FORM_HOSTS
        .iter()
        .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
        .then_some(url)
}

#[cfg(not(debug_assertions))]
fn is_allowed_origin(origin: &header::HeaderValue) -> bool {
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    origin == config().base_url || allowed_form_url(origin).is_some()
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

struct RedeemEntry {
    id: String,
    nonce: String,
    hca_token: String,
    hca_expires_at: Instant,
    created: Instant,
}

static REDEEM_REGISTRY: OnceLock<Mutex<Vec<RedeemEntry>>> = OnceLock::new();

fn redeem_registry() -> MutexGuard<'static, Vec<RedeemEntry>> {
    let mut entries = REDEEM_REGISTRY
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap();
    entries.retain(|entry| entry.created.elapsed() < REDEEM_TTL);
    entries
}

fn redeem_register(id: String, nonce: String, hca_token: String, hca_expires_at: Instant) {
    let mut entries = redeem_registry();
    entries.retain(|entry| entry.id != id);
    entries.push(RedeemEntry {
        id,
        nonce,
        hca_token,
        hca_expires_at,
        created: Instant::now(),
    });
}

fn redeem_take(id: &str, nonce: &str) -> Option<(String, Instant)> {
    let mut entries = redeem_registry();
    let pos = entries.iter().position(|entry| entry.id == id)?;
    if entries[pos].nonce != nonce {
        return None;
    }
    let entry = entries.remove(pos);
    Some((entry.hca_token, entry.hca_expires_at))
}

struct HcaTokenEntry {
    id: String,
    hca_token: String,
    expires_at: Instant,
}

static HCA_TOKEN_REGISTRY: OnceLock<Mutex<Vec<HcaTokenEntry>>> = OnceLock::new();

fn hca_token_registry() -> MutexGuard<'static, Vec<HcaTokenEntry>> {
    let mut entries = HCA_TOKEN_REGISTRY
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap();
    let now = Instant::now();
    entries.retain(|entry| now < entry.expires_at);
    entries
}

fn hca_token_register(id: String, hca_token: String, expires_at: Instant) {
    let mut entries = hca_token_registry();
    entries.retain(|entry| entry.id != id);
    entries.push(HcaTokenEntry {
        id,
        hca_token,
        expires_at,
    });
}

fn hca_token_get(id: &str) -> Option<String> {
    hca_token_registry()
        .iter()
        .find(|entry| entry.id == id)
        .map(|entry| entry.hca_token.clone())
}

fn hca_token_take(id: &str) -> Option<String> {
    let mut entries = hca_token_registry();
    let pos = entries.iter().position(|entry| entry.id == id)?;
    Some(entries.remove(pos).hca_token)
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
        .insert_header(("Cache-Control", "no-store"))
        .body(page)
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
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
    let Some(mut form_url) = allowed_form_url(fillout_url) else {
        return HttpResponse::BadRequest().body("redirect target not allowed");
    };

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

    let (token, expires_in) = match serde_json::from_str::<TokenResponse>(&body) {
        Ok(body) => (body.access_token, body.expires_in),
        Err(_) => return HttpResponse::BadGateway().finish(),
    };

    let hca_ttl = expires_in
        .map(|seconds| HCA_TOKEN_TTL.min(Duration::from_secs(seconds)))
        .unwrap_or(HCA_TOKEN_TTL);

    let redeem_id = random_token();
    redeem_register(
        redeem_id.clone(),
        nonce.to_string(),
        token,
        Instant::now() + hca_ttl,
    );

    form_url.set_fragment(Some(&format!("{REDEEM_FRAGMENT}={redeem_id}")));

    HttpResponse::SeeOther()
        .append_header(("Location", form_url.as_str()))
        .finish()
}

#[derive(serde::Deserialize)]
struct RedeemArgs {
    redeem: String,
    nonce: String,
}

#[get("/redeem")]
async fn redeem(query: web::Query<RedeemArgs>) -> impl Responder {
    let Some((hca_token, hca_expires_at)) =
        redeem_take(query.redeem.as_str(), query.nonce.as_str())
    else {
        return HttpResponse::BadRequest().finish();
    };

    let opaque_token = random_token();
    hca_token_register(opaque_token.clone(), hca_token, hca_expires_at);

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

    if !response.status().is_success() {
        return HttpResponse::BadGateway()
            .body(format!("hack club auth returned {}", response.status()));
    }

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
        .insert_header(("Cache-Control", "no-store"))
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
