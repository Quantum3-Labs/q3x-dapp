use std::cell::RefCell;

use candid::CandidType;
use ic_cdk::management_canister::{VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId, VetKDPublicKeyArgs};
use ic_vetkeys::{
    DerivedPublicKey, EncryptedVetKey, TransportSecretKey,
    VetKey,
};
use serde::{Deserialize, Serialize};

#[derive(CandidType, Serialize, Deserialize, Clone)]
pub struct KeyResponse {
    pub key_hex: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone)]
pub struct ErrorResponse {
    pub error: String,
}

pub type VetKeyResult<T> = Result<T, ErrorResponse>;


const PUBLIC_KEY_ERROR: &str = "PublicKeyError";
const TRANSPORT_KEY_ERROR: &str = "TransportKeyError";
const DERIVE_KEY_ERROR: &str = "DeriveKeyError";
const VETKEY_ERROR: &str = "VetKeyError";

thread_local! {
    static VETKEY_ID: RefCell<VetKDKeyId> = RefCell::new(VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "dfx_test_key".to_string(),
    });
}

/// Sets the VetKD key ID (called from init)
///
/// Configures the VetKD key identifier based on the deployment environment.
/// This should be called once during canister initialization to set the
/// appropriate key for the target environment.
///
/// # Arguments
///
/// * `env` - Environment string ("production", "test", or other for local development).
///
/// # Behavior
///
/// Updates the thread-local VETKEY_ID with environment-specific key configuration:
/// - "production" -> "key_1"
/// - "test" -> "test_key_1"  
/// - other -> "dfx_test_key" (for local development)
pub fn set_vetkey_id(env: &str) {
    let key_id = VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: match env {
            "production" => "key_1",
            "test" => "test_key_1", 
            _ => "dfx_test_key",
        }.to_string(),
    };
    
    VETKEY_ID.with(|id| {
        *id.borrow_mut() = key_id;
    });
}

/// Gets the current VetKD key ID
///
/// Retrieves the currently configured VetKD key identifier from thread-local storage.
/// This key ID is used for all VetKD operations within the canister.
///
/// # Returns
///
/// * `VetKDKeyId` - The current VetKD key identifier with curve and name configuration.
fn get_vetkey_id() -> VetKDKeyId {
    VETKEY_ID.with(|id| id.borrow().clone())
}

/// Derives a 32-byte seed by combining wallet ID and data for cryptographic operations.
///
/// Creates a deterministic seed by concatenating wallet ID and data, then normalizing
/// to exactly 32 bytes (padding with zeros or truncating as needed).
///
/// # Arguments
///
/// * `wallet_id` - The wallet's unique identifier string.
/// * `data` - Additional data bytes to include in the seed derivation.
///
/// # Returns
///
/// * `Vec<u8>` - A 32-byte seed vector suitable for cryptographic operations.
pub fn derive_seed_simple(wallet_id: &str, data: &[u8]) -> Vec<u8> {
    let mut seed = Vec::new();
    seed.extend_from_slice(wallet_id.as_bytes());
    seed.extend_from_slice(data);

    if seed.len() < 32 {
        seed.resize(32, 0);
    } else if seed.len() > 32 {
        seed.truncate(32);
    }

    seed
}

/// Retrieves the VetKD public key for a given context.
///
/// Requests a VetKD public key from the IC management canister for encryption
/// operations, returned as a hexadecimal string.
///
/// # Arguments
///
/// * `context` - Context bytes for key derivation (typically wallet-specific data).
///
/// # Returns
///
/// * `VetKeyResult<KeyResponse>` - Public key in hex format or error response.
pub async fn get_verification_public_key(context: &[u8]) -> VetKeyResult<KeyResponse> {
    let request = VetKDPublicKeyArgs {
        canister_id: None,
        context: context.to_vec(),
        key_id: get_vetkey_id(),
    };

    match ic_cdk::management_canister::vetkd_public_key(&request).await {
        Ok(response) => Ok(KeyResponse {
            key_hex: hex::encode(response.public_key),
        }),
        Err(err) => Err(ErrorResponse {
            error: format!("Failed to get public key: {:?}", err),
        }),
    }
}

/// Derives an encrypted VetKD key using the provided context and input data.
///
/// Requests a derived key from the IC management canister, encrypted with the transport
/// public key for secure delivery. Used for decryption after transport key decryption.
///
/// # Arguments
///
/// * `context` - Context bytes for key derivation (typically wallet-specific data).
/// * `input` - Additional input data for key derivation (e.g., identity bytes).
/// * `transport_public_key` - Public key used to encrypt the derived key for transport.
///
/// # Returns
///
/// * `VetKeyResult<KeyResponse>` - Encrypted derived key in hex format or error response.
pub async fn get_derive_key(
    context: &[u8],
    input: Vec<u8>,
    transport_public_key: Vec<u8>,
) -> VetKeyResult<KeyResponse> {
    let request = VetKDDeriveKeyArgs {
        input,
        context: context.to_vec(),
        key_id: get_vetkey_id(),
        transport_public_key,
    };

    match ic_cdk::management_canister::vetkd_derive_key(&request).await {
        Ok(response) => Ok(KeyResponse {
            key_hex: hex::encode(response.encrypted_key),
        }),
        Err(err) => Err(ErrorResponse {
            error: format!("Failed to derive key: {:?}", err),
        }),
    }
}

/// Retrieves and deserializes the IBE public key for a specific wallet.
///
/// Uses wallet_id for key derivation so all wallet members can decrypt shared data
/// rather than storing separate encrypted versions for each signer.
///
/// # Arguments
///
/// * `wallet_id` - The wallet's unique identifier for key derivation.
///
/// # Returns
///
/// * `Result<DerivedPublicKey, String>` - The deserialized IBE public key or error message.
pub async fn get_wallet_public_key(wallet_id: &str) -> Result<DerivedPublicKey, String> {
    let wallet_context = format!("wallet_{}", wallet_id).as_bytes().to_vec();
    let public_key_response = get_verification_public_key(&wallet_context)
        .await
        .map_err(|_| PUBLIC_KEY_ERROR)?;

    let decoded_key = hex::decode(public_key_response.key_hex).map_err(|_| PUBLIC_KEY_ERROR)?;
    let ibe_public_key =
        DerivedPublicKey::deserialize(&decoded_key).map_err(|_| PUBLIC_KEY_ERROR)?;

    Ok(ibe_public_key)
}

/// Retrieves the IBE decryption key for a wallet using VetKD key derivation.
///
/// Uses wallet_id for key derivation so all wallet members can decrypt shared data.
/// Performs the complete VetKD flow: transport key creation, public/derived key requests,
/// and final key decryption/verification.
///
/// # Arguments
///
/// * `wallet_id` - The wallet's unique identifier for key derivation.
///
/// # Returns
///
/// * `Result<VetKey, String>` - IBE decryption key or error message.
pub async fn get_wallet_decryption_key(wallet_id: &str) -> Result<VetKey, String> {
    // 1. Create transport key
    let dummy_seed = vec![0; 32];
    let transport_secret_key =
        TransportSecretKey::from_seed(dummy_seed).map_err(|_| TRANSPORT_KEY_ERROR)?;

    // 2. Get the public key and derive key
    let wallet_context = format!("wallet_{}", wallet_id).as_bytes().to_vec();
    let public_key_response = get_verification_public_key(&wallet_context)
        .await
        .map_err(|_| PUBLIC_KEY_ERROR)?;

    // Derive the key using the public key
    let derive_key_response = get_derive_key(
        &wallet_context,
        wallet_id.as_bytes().to_vec(),
        transport_secret_key.public_key().to_vec(),
    )
    .await
    .map_err(|_| DERIVE_KEY_ERROR)?;

    // 3. Decrypt and verify
    let ibe_public_key = DerivedPublicKey::deserialize(
        &hex::decode(public_key_response.key_hex).map_err(|_| PUBLIC_KEY_ERROR)?,
    )
    .map_err(|_| PUBLIC_KEY_ERROR)?;

    let encrypted_vetkey = EncryptedVetKey::deserialize(
        &hex::decode(derive_key_response.key_hex).map_err(|_| DERIVE_KEY_ERROR)?,
    )
    .map_err(|_| VETKEY_ERROR)?;

    let ibe_decryption_key = encrypted_vetkey
        .decrypt_and_verify(&transport_secret_key, &ibe_public_key, wallet_id.as_bytes())
        .map_err(|_| VETKEY_ERROR)?;

    Ok(ibe_decryption_key)
}
