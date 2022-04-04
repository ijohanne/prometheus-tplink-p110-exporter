use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{anyhow, bail, Result};
use clap::Parser;
use prometheus::{GaugeVec, Opts, Registry};
use rand::rngs::OsRng;
use rsa::{
    pkcs8::{LineEnding, ToPublicKey},
    PaddingScheme, RsaPrivateKey, RsaPublicKey,
};
use serde_json::json;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};
use warp::{Filter, Rejection, Reply};

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

pub type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
pub type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Clone)]
pub struct PrometheusStats {
    power_usage: GaugeVec,
    rssi: GaugeVec,
    registry: Registry,
}

impl PrometheusStats {
    pub fn new() -> Self {
        let instance = Self {
            power_usage: GaugeVec::new(
                Opts::new("power_usage", "Power usage"),
                &["device_id", "nickname"],
            )
            .expect("metric can be created"),

            rssi: GaugeVec::new(Opts::new("rssi", "RSSI"), &["device_id", "nickname"])
                .expect("metric can be created"),
            registry: Registry::new(),
        };
        instance
            .registry
            .register(Box::new(instance.power_usage.clone()))
            .expect("collector can be registered");
        instance
            .registry
            .register(Box::new(instance.rssi.clone()))
            .expect("collector can be registered");
        instance
    }
}

impl Default for PrometheusStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    hosts: Vec<String>,

    #[clap(long)]
    username: String,

    #[clap(long)]
    password: String,

    #[clap(long, default_value = "9984")]
    listen_port: u64,

    #[clap(long, default_value = "127.0.0.1")]
    listen_address: String,
}

pub struct RsaKeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RsaKeyPair {
    pub fn new() -> Result<Self> {
        let mut rng = OsRng;
        let bits = 1_024;
        let private_key = RsaPrivateKey::new(&mut rng, bits)?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn get_public_pem(&self) -> Result<String, rsa::pkcs8::Error> {
        self.public_key.to_public_key_pem_with_le(LineEnding::LF)
    }

    pub fn get_private_key(&self) -> RsaPrivateKey {
        self.private_key.clone()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let stats = PrometheusStats::default();
    let metrics_route =
        warp::path!("metrics").and(with_stats(stats.clone())).and_then(metrics_handler);

    tokio::task::spawn(data_collector(
        stats,
        args.username.clone(),
        args.password.clone(),
        args.hosts.clone(),
    ));

    warp::serve(metrics_route)
        .run(
            format!("{}:{}", args.listen_address, args.listen_port)
                .parse::<std::net::SocketAddr>()
                .expect("listen address correct"),
        )
        .await;

    Ok(())
}

fn with_stats(
    stats: PrometheusStats,
) -> impl Filter<Extract = (PrometheusStats,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || stats.clone())
}

async fn data_collector(
    stats: PrometheusStats,
    username: String,
    password: String,
    hosts: Vec<String>,
) {
    loop {
        for host in &hosts {
            match reqwest::Client::builder()
                .http1_title_case_headers()
                .user_agent(APP_USER_AGENT)
                .cookie_store(true)
                .build()
            {
                Ok(client) => match handshake(&client, host).await {
                    Ok(key) => {
                        let aes_key = &key[0..16];
                        let aes_iv = &key[16..32];
                        match login(&client, host, aes_key, aes_iv, &username, &password).await {
                            Ok(token) => {
                                match get_device_info(&client, host, aes_key, aes_iv, &token).await
                                {
                                    Ok(device_info) => {
                                        stats
                                            .rssi
                                            .with_label_values(&[
                                                &device_info.0.clone(),
                                                &device_info.1.clone(),
                                            ])
                                            .set(device_info.2 as f64);
                                        match get_current_energy_usage(&client, host, aes_key, aes_iv, &token).await {
                                                    Ok(power_usage) => {
                                                        stats.power_usage.with_label_values(&[&device_info.0.clone(), &device_info.1.clone()]).set(power_usage as f64);
                                                    },
                                                        Err(e) => println!("Could not obtain power usage level for {} due to {}", host, e),
                                                }
                                    }
                                    Err(e) => println!(
                                        "Could not obtain device info for {} due to {}",
                                        host, e
                                    ),
                                }
                            }
                            Err(e) => {
                                println!("Could not get token for host {} due to {}", host, e)
                            }
                        }
                    }
                    Err(e) => println!("Could not handshake host {} due to {}", host, e),
                },
                Err(e) => println!("Could not obtain client due to {}", e),
            }
        }
    }
}

async fn metrics_handler(stats: PrometheusStats) -> Result<impl Reply, Rejection> {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&stats.registry.gather(), &mut buffer) {
        eprintln!("could not encode custom metrics: {}", e);
    };
    let mut res = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("custom metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        eprintln!("could not encode prometheus metrics: {}", e);
    };
    let res_custom = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("prometheus metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();

    res.push_str(&res_custom);
    Ok(res)
}

async fn handshake(client: &reqwest::Client, host: &str) -> Result<Vec<u8>> {
    let rsa_key_pair = RsaKeyPair::new()?;

    let payload = json!( {
        "method": "handshake",
        "params": {
            "key": rsa_key_pair.get_public_pem()?,
            "requestTimeMils": SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
        }
    });
    let res: Value =
        client.post(format!("http://{}/app", host)).json(&payload).send().await?.json().await?;

    let key_encrypted = res
        .get("result")
        .ok_or_else(|| anyhow!("Incorrect JSON structure in response"))?
        .get("key")
        .ok_or_else(|| anyhow!("Incorrect JSON structure in response"))?
        .as_str()
        .ok_or_else(|| anyhow!("Incorrect JSON structure in response"))?;

    Ok(rsa_key_pair
        .get_private_key()
        .decrypt(PaddingScheme::PKCS1v15Encrypt, &base64::decode(&key_encrypted.as_bytes())?)?)
}

async fn login(
    client: &reqwest::Client,
    host: &str,
    aes_key: &[u8],
    aes_iv: &[u8],
    username: &str,
    password: &str,
) -> Result<String> {
    let insecure_payload = json!( {
        "method": "login_device",
    "params":{
        "username": mime_encode( sha_digest_username(username)?.as_bytes() , true)?,
        "password": mime_encode( password.as_bytes(), true )?,
    },
        "requestTimeMils": SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
    });

    let encrypted_inner_payload =
        match encrypt_aes(aes_key, aes_iv, insecure_payload.to_string().as_bytes()) {
            Ok(payload) => payload,
            Err(e) => bail!("Could not encrypt payload due to {}", e),
        };

    let secured_payload = json!( {
        "method": "securePassthrough",
        "params": {
            "request": mime_encode(&encrypted_inner_payload, false )?,
        },
    } );

    let res: Value = client
        .post(format!("http://{}/app", host))
        .json(&secured_payload)
        .send()
        .await?
        .json()
        .await?;

    let decrypted = match decrypt_aes(
        aes_key,
        aes_iv,
        match &base64::decode(
            res.get("result")
                .ok_or_else(|| anyhow!("Incorrect JSON structure in response"))?
                .get("response")
                .ok_or_else(|| anyhow!("Incorrect JSON structure in response"))?
                .as_str()
                .ok_or_else(|| anyhow!("Incorrect JSON structure in response"))?,
        ) {
            Ok(res) => res,
            Err(e) => bail!("Could not decode due to {}", e),
        },
    ) {
        Ok(ref res) => match str::from_utf8(res) {
            Ok(decrypted_payload) => decrypted_payload.to_owned(),
            Err(_) => bail!("Could not parse as UTF-8 data after decoding"),
        },
        Err(e) => bail!("Could not decrypt due to {}", e),
    };

    match serde_json::from_str::<Value>(&decrypted) {
        Ok(inner_json) => Ok(inner_json
            .get("result")
            .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?
            .get("token")
            .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?
            .as_str()
            .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?
            .to_string()),
        Err(e) => bail!("Failed to parse inner JSON due to {}", e),
    }
}

async fn get_device_info(
    client: &reqwest::Client,
    host: &str,
    aes_key: &[u8],
    aes_iv: &[u8],
    token: &str,
) -> Result<(String, String, i64)> {
    let insecure_payload = json!( {
        "method": "get_device_info",
        "requestTimeMils": SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
    });

    let encrypted_inner_payload =
        match encrypt_aes(aes_key, aes_iv, insecure_payload.to_string().as_bytes()) {
            Ok(payload) => payload,
            Err(e) => bail!("Could not encrypt payload due to {}", e),
        };

    let secured_payload = json!( {
        "method": "securePassthrough",
        "params": {
            "request": mime_encode(&encrypted_inner_payload, false )?,
        },
    } );

    let res: Value = client
        .post(format!("http://{}/app?token={}", host, token))
        .json(&secured_payload)
        .send()
        .await?
        .json()
        .await?;

    let decrypted = match decrypt_aes(
        aes_key,
        aes_iv,
        match &base64::decode(
            res.get("result")
                .ok_or_else(|| anyhow!("Incorrect JSON structure in response"))?
                .get("response")
                .ok_or_else(|| anyhow!("Incorrect JSON structure in response"))?
                .as_str()
                .ok_or_else(|| anyhow!("Incorrect JSON structure in response"))?,
        ) {
            Ok(res) => res,
            Err(e) => bail!("Could not decode due to {}", e),
        },
    ) {
        Ok(ref res) => match str::from_utf8(res) {
            Ok(decrypted_payload) => decrypted_payload.to_owned(),
            Err(_) => bail!("Could not parse as UTF-8 data after decoding"),
        },
        Err(e) => bail!("Could not decrypt due to {}", e),
    };

    match serde_json::from_str::<Value>(&decrypted) {
        Ok(inner_json) => Ok((
            inner_json
                .get("result")
                .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?
                .get("device_id")
                .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?
                .as_str()
                .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?
                .to_string(),
            inner_json
                .get("result")
                .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?
                .get("nickname")
                .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?
                .as_str()
                .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?
                .to_string(),
            inner_json
                .get("result")
                .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?
                .get("rssi")
                .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?
                .as_i64()
                .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?,
        )),
        Err(e) => bail!("Failed to parse inner JSON due to {}", e),
    }
}

async fn get_current_energy_usage(
    client: &reqwest::Client,
    host: &str,
    aes_key: &[u8],
    aes_iv: &[u8],
    token: &str,
) -> Result<u64> {
    let insecure_payload = json!( {
        "method": "get_energy_usage",
        "requestTimeMils": SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
    });

    let encrypted_inner_payload =
        match encrypt_aes(aes_key, aes_iv, insecure_payload.to_string().as_bytes()) {
            Ok(payload) => payload,
            Err(e) => bail!("Could not encrypt payload due to {}", e),
        };

    let secured_payload = json!( {
        "method": "securePassthrough",
        "params": {
            "request": mime_encode(&encrypted_inner_payload, false )?,
        },
    } );

    let res: Value = client
        .post(format!("http://{}/app?token={}", host, token))
        .json(&secured_payload)
        .send()
        .await?
        .json()
        .await?;

    let decrypted = match decrypt_aes(
        aes_key,
        aes_iv,
        match &base64::decode(
            res.get("result")
                .ok_or_else(|| anyhow!("Incorrect JSON structure in response"))?
                .get("response")
                .ok_or_else(|| anyhow!("Incorrect JSON structure in response"))?
                .as_str()
                .ok_or_else(|| anyhow!("Incorrect JSON structure in response"))?,
        ) {
            Ok(res) => res,
            Err(e) => bail!("Could not decode due to {}", e),
        },
    ) {
        Ok(ref res) => match str::from_utf8(res) {
            Ok(decrypted_payload) => decrypted_payload.to_owned(),
            Err(_) => bail!("Could not parse as UTF-8 data after decoding"),
        },
        Err(e) => bail!("Could not decrypt due to {}", e),
    };

    match serde_json::from_str::<Value>(&decrypted) {
        Ok(inner_json) => Ok(inner_json
            .get("result")
            .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?
            .get("current_power")
            .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?
            .as_u64()
            .ok_or_else(|| anyhow!("Incorrect JSON structure in decrypted response"))?),
        Err(e) => bail!("Failed to parse inner JSON due to {}", e),
    }
}

fn sha_digest_username(input: &str) -> Result<String> {
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    use core::fmt::Write;
    let mut s = String::with_capacity(2 * &result.len());
    for byte in &result {
        write!(s, "{:02x}", byte)?;
    }
    Ok(s)
}

fn mime_encode(input: &[u8], chunk: bool) -> Result<String> {
    if chunk {
        match base64::encode(input)
            .as_bytes()
            .chunks(76)
            .map(str::from_utf8)
            .collect::<Result<Vec<&str>, _>>()
        {
            Ok(chunks) => Ok(chunks.join("\n")),
            Err(e) => bail!("Could not mime encode due to {}", e),
        }
    } else {
        Ok(base64::encode(input))
    }
}

fn encrypt_aes(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let block_size = 16;
    let padding_length = block_size - plaintext.len() % block_size;
    let mut buffer = vec![0; padding_length + plaintext.len()];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    match Aes128CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
    {
        Ok(encrypted) => Ok(encrypted.to_owned()),
        Err(e) => bail!("Can not encrypted plaintext due to {}", e),
    }
}

fn decrypt_aes(key: &[u8], iv: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
    let mut buffer = encrypted.to_vec();
    match Aes128CbcDec::new(key.into(), iv.into()).decrypt_padded_mut::<Pkcs7>(&mut buffer) {
        Ok(encrypted) => Ok(encrypted.to_owned()),
        Err(e) => bail!("Can not decrypted payload due to {}", e),
    }
}
