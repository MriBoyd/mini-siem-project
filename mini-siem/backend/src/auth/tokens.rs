use serde::{Deserialize, Serialize};
use rand::{thread_rng, Rng};
use base64::{Engine as _, engine::general_purpose};

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

pub fn generate_refresh_token() -> String {
    let mut rng = thread_rng();
    let token: [u8; 32] = rng.gen();
    general_purpose::STANDARD.encode(token)
}
