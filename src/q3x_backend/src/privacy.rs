use std::collections::{HashMap, HashSet};

use candid::Principal;
use ic_vetkeys::{DerivedPublicKey, IbeCiphertext, IbeIdentity, IbeSeed, VetKey};

use crate::{
    vetkey::{derive_seed_simple, get_wallet_decryption_key, get_wallet_public_key},
    wallet::Wallet,
};

const ENCODING_ERROR: &str = "EncodingError";
const SEED_ERROR: &str = "SeedError";
const CIPHERTEXT_ERROR: &str = "CiphertextError";
const DECODE_ERROR: &str = "DecodeError";

// ENCRYPTION

/// Encrypts a single principal using IBE with the provided public key.
///
/// Encodes the principal, derives a deterministic seed, and encrypts using
/// Identity-Based Encryption with wallet_id as the identity.
///
/// # Arguments
///
/// * `signer` - The principal to encrypt.
/// * `wallet_id` - The wallet identifier used as IBE identity.
/// * `ibe_public_key` - The IBE public key for encryption.
///
/// # Returns
///
/// * `Result<String, String>` - Encrypted principal as hex string or error message.
async fn encrypt_single_principal_with_key(
    signer: Principal,
    wallet_id: &str,
    ibe_public_key: &DerivedPublicKey,
) -> Result<String, String> {
    // 1. Encode the principal to bytes
    let principal_bytes = candid::encode_args((signer,)).map_err(|_| ENCODING_ERROR)?;

    // 2. Get bytes from wallet-id and principal
    let seed_bytes = derive_seed_simple(wallet_id, signer.as_slice());

    // 3. Create the IBE seed
    let seed = IbeSeed::from_bytes(&seed_bytes).map_err(|_| SEED_ERROR)?;

    // 4. Encrypt using IBE
    let ibe_ciphertext = IbeCiphertext::encrypt(
        ibe_public_key,
        &IbeIdentity::from_bytes(wallet_id.as_bytes()),
        &principal_bytes,
        &seed,
    );

    // 5. Return the encrypted data as a hex string
    Ok(hex::encode(ibe_ciphertext.serialize()))
}


/// Encrypts multiple principals using VetKD-derived keys.
///
/// Retrieves the wallet's IBE public key once and encrypts each principal
/// individually, returning a vector of hex-encoded encrypted strings.
///
/// # Arguments
///
/// * `signers` - Array of principals to encrypt.
/// * `wallet_id` - The wallet identifier for key derivation.
///
/// # Returns
///
/// * `Result<Vec<String>, String>` - Vector of encrypted principals as hex strings or error message.
pub async fn encrypt_principals_with_vetkeys(
    signers: &[Principal],
    wallet_id: &str,
) -> Result<Vec<String>, String> {
    let mut encrypted_signers = Vec::new();

    // Get the IBE public key
    let ibe_public_key = get_wallet_public_key(wallet_id).await?;

    // Encrypt each signer individually
    for signer in signers {
        let encrypted_hex =
            encrypt_single_principal_with_key(*signer, wallet_id, &ibe_public_key).await?;
        encrypted_signers.push(encrypted_hex);
    }

    Ok(encrypted_signers)
}


/// Encrypts a message using IBE with the provided public key.
///
/// Derives a deterministic seed from wallet_id and message, then encrypts
/// using Identity-Based Encryption with wallet_id as the identity.
///
/// # Arguments
///
/// * `message` - The message bytes to encrypt.
/// * `wallet_id` - The wallet identifier used as IBE identity.
/// * `ibe_public_key` - The IBE public key for encryption.
///
/// # Returns
///
/// * `Result<Vec<u8>, String>` - Encrypted message bytes or error message.
async fn encrypt_message_with_key(
    message: &Vec<u8>,
    wallet_id: &str,
    ibe_public_key: &DerivedPublicKey,
) -> Result<Vec<u8>, String> {
    // 1. Get seed bytes from wallet-id and message
    let seed_bytes = derive_seed_simple(wallet_id, &message);

    // 2. Create the IBE seed
    let seed = IbeSeed::from_bytes(&seed_bytes).map_err(|_| SEED_ERROR)?;

    // 3. Encrypt using IBE
    let ibe_ciphertext = IbeCiphertext::encrypt(
        ibe_public_key,
        &IbeIdentity::from_bytes(wallet_id.as_bytes()),
        &message,
        &seed,
    );

    // 4. Return the encrypted data
    Ok(ibe_ciphertext.serialize())
}


/// Encrypts a message using VetKD-derived keys.
///
/// Retrieves the wallet's IBE public key and encrypts the message,
/// returning the encrypted bytes.
///
/// # Arguments
///
/// * `message` - The message bytes to encrypt.
/// * `wallet_id` - The wallet identifier for key derivation.
///
/// # Returns
///
/// * `Result<Vec<u8>, String>` - Encrypted message bytes or error message.
pub async fn encrypt_message_with_vetkeys(
    message: &Vec<u8>,
    wallet_id: &str,
) -> Result<Vec<u8>, String> {
    // Get the IBE public key using helper
    let ibe_public_key = get_wallet_public_key(wallet_id).await?;

    encrypt_message_with_key(message, wallet_id, &ibe_public_key).await
}


/// Encrypts metadata using VetKD-derived keys.
///
/// Retrieves the wallet's IBE public key, encodes the metadata string,
/// and encrypts it using Identity-Based Encryption.
///
/// # Arguments
///
/// * `metadata` - The metadata string to encrypt.
/// * `wallet_id` - The wallet identifier for key derivation.
///
/// # Returns
///
/// * `Result<String, String>` - Encrypted metadata as hex string or error message.
pub async fn encrypt_metadata_with_vetkeys(
    metadata: String,
    wallet_id: &str,
) -> Result<String, String> {
    // Get the IBE public key
    let ibe_public_key = get_wallet_public_key(wallet_id).await?;

    // 1. Encode the metadata to bytes
    let metadata_bytes = candid::encode_args((metadata,)).map_err(|_| ENCODING_ERROR)?;

    // 2. Get seed bytes from wallet-id and metadata
    let seed_bytes = derive_seed_simple(wallet_id, &metadata_bytes);

    // 3. Create the IBE seed
    let seed = IbeSeed::from_bytes(&seed_bytes).map_err(|_| SEED_ERROR)?;

    // 4. Encrypt using IBE
    let ibe_ciphertext = IbeCiphertext::encrypt(
        &ibe_public_key,
        &IbeIdentity::from_bytes(wallet_id.as_bytes()),
        &metadata_bytes,
        &seed,
    );

    // 5. Return the encrypted data as a hex string
    Ok(hex::encode(ibe_ciphertext.serialize()))
}


/// Encrypts both a principal and message using VetKD-derived keys.
///
/// Retrieves the wallet's IBE public key once and encrypts both the principal
/// and message, optimizing performance by reusing the same key.
///
/// # Arguments
///
/// * `signer` - The principal to encrypt.
/// * `message` - The message bytes to encrypt.
/// * `wallet_id` - The wallet identifier for key derivation.
///
/// # Returns
///
/// * `Result<(String, Vec<u8>), String>` - Tuple of (encrypted principal as hex, encrypted message bytes) or error message.
pub async fn encrypt_principal_and_message_with_vetkeys(
    signer: Principal,
    message: &Vec<u8>,
    wallet_id: &str,
) -> Result<(String, Vec<u8>), String> {
    // Get the IBE public key once
    let ibe_public_key = get_wallet_public_key(wallet_id).await?;

    let encrypted_principal =
        encrypt_single_principal_with_key(signer, wallet_id, &ibe_public_key).await?;

    let encrypted_message = encrypt_message_with_key(message, wallet_id, &ibe_public_key).await?;

    Ok((encrypted_principal, encrypted_message))
}

// DECRYPTION
/// Decrypts a single principal from hex-encoded encrypted data.
///
/// Decodes the hex string, deserializes the IBE ciphertext, decrypts using
/// the provided key, and decodes back to a Principal.
///
/// # Arguments
///
/// * `encrypted_hex` - The hex-encoded encrypted principal data.
/// * `ibe_decryption_key` - The IBE decryption key.
///
/// # Returns
///
/// * `Result<Principal, String>` - The decrypted principal or error message.
async fn decrypt_single_principal_hex(
    encrypted_hex: &str,
    ibe_decryption_key: &VetKey,
) -> Result<Principal, String> {
    // 1. Decode hex to bytes
    let encrypted_data = hex::decode(encrypted_hex).map_err(|_| CIPHERTEXT_ERROR)?;

    // 2. Deserialize the ciphertext
    let ibe_ciphertext =
        IbeCiphertext::deserialize(&encrypted_data).map_err(|_| CIPHERTEXT_ERROR)?;

    // 3. Decrypt the ciphertext
    let decrypted_bytes = ibe_ciphertext
        .decrypt(ibe_decryption_key)
        .map_err(|_| CIPHERTEXT_ERROR)?;

    // 4. Decode back to principal
    let (principal,): (Principal,) =
        candid::decode_args(&decrypted_bytes).map_err(|_| DECODE_ERROR)?;

    Ok(principal)
}


/// Decrypts multiple principals from a list of hex-encoded encrypted data.
///
/// Retrieves the IBE decryption key for the specified wallet and decrypts
/// each hex-encoded principal in the provided list.
///
/// # Arguments
///
/// * `encrypted_hex_list` - A slice of hex-encoded encrypted principal data.
/// * `wallet_id` - The wallet identifier used to retrieve the decryption key.
///
/// # Returns
///
/// * `Result<Vec<Principal>, String>` - Vector of decrypted principals or error message.
pub async fn decrypt_principals_with_vetkeys(
    encrypted_hex_list: &[String],
    wallet_id: &str,
) -> Result<Vec<Principal>, String> {
    // Get the IBE decryption key using helper
    let ibe_decryption_key = get_wallet_decryption_key(wallet_id).await?;

    // Decrypt each principal
    let mut decrypted_principals = Vec::new();
    for encrypted_hex in encrypted_hex_list {
        let principal = decrypt_single_principal_hex(encrypted_hex, &ibe_decryption_key).await?;
        decrypted_principals.push(principal);
    }

    Ok(decrypted_principals)
}

/// Decrypts a single message from hex-encoded encrypted data.
///
/// Decodes the hex string, deserializes the IBE ciphertext, and decrypts using
/// the provided key to return the original message bytes.
///
/// # Arguments
///
/// * `encrypted_hex` - The hex-encoded encrypted message data.
/// * `ibe_decryption_key` - The IBE decryption key.
///
/// # Returns
///
/// * `Result<Vec<u8>, String>` - The decrypted message bytes or error message.
async fn decrypt_single_message_hex(
    encrypted_hex: &str,
    ibe_decryption_key: &VetKey,
) -> Result<Vec<u8>, String> {
    // 1. Decode hex to bytes
    let encrypted_data = hex::decode(encrypted_hex).map_err(|_| CIPHERTEXT_ERROR)?;

    // 2. Deserialize the ciphertext
    let ibe_ciphertext =
        IbeCiphertext::deserialize(&encrypted_data).map_err(|_| CIPHERTEXT_ERROR)?;

    // 3. Decrypt the ciphertext
    let decrypted_bytes = ibe_ciphertext
        .decrypt(ibe_decryption_key)
        .map_err(|_| CIPHERTEXT_ERROR)?;

    Ok(decrypted_bytes)
}

/// Decrypts a message using wallet-specific VetKeys.
///
/// Retrieves the IBE decryption key for the specified wallet and decrypts
/// the hex-encoded message data.
///
/// # Arguments
///
/// * `encrypted_hex` - The hex-encoded encrypted message data.
/// * `wallet_id` - The wallet identifier used to retrieve the decryption key.
///
/// # Returns
///
/// * `Result<Vec<u8>, String>` - The decrypted message bytes or error message.
pub async fn decrypt_message_with_vetkeys(
    encrypted_hex: &str,
    wallet_id: &str,
) -> Result<Vec<u8>, String> {
    let ibe_decryption_key = get_wallet_decryption_key(wallet_id).await?;
    decrypt_single_message_hex(encrypted_hex, &ibe_decryption_key).await
}

/// Decrypts multiple messages from a list of hex-encoded encrypted data.
///
/// Retrieves the IBE decryption key for the specified wallet and decrypts
/// each hex-encoded message in the provided list.
///
/// # Arguments
///
/// * `encrypted_hex_list` - A slice of hex-encoded encrypted message data.
/// * `wallet_id` - The wallet identifier used to retrieve the decryption key.
///
/// # Returns
///
/// * `Result<Vec<Vec<u8>>, String>` - Vector of decrypted message bytes or error message.
pub async fn decrypt_messages_with_vetkeys(
    encrypted_hex_list: &[String],
    wallet_id: &str,
) -> Result<Vec<Vec<u8>>, String> {
    let ibe_decryption_key = get_wallet_decryption_key(wallet_id).await?;

    let mut decrypted_messages = Vec::new();
    for encrypted_hex in encrypted_hex_list {
        let decrypted_msg = decrypt_single_message_hex(encrypted_hex, &ibe_decryption_key).await?;
        decrypted_messages.push(decrypted_msg);
    }

    Ok(decrypted_messages)
}

/// Decrypts a single metadata string from hex-encoded encrypted data.
///
/// Decodes the hex string, deserializes the IBE ciphertext, decrypts using
/// the provided key, and decodes back to a metadata string.
///
/// # Arguments
///
/// * `encrypted_hex` - The hex-encoded encrypted metadata data.
/// * `ibe_decryption_key` - The IBE decryption key.
///
/// # Returns
///
/// * `Result<String, String>` - The decrypted metadata string or error message.
async fn decrypt_single_metadata_hex(
    encrypted_hex: &str,
    ibe_decryption_key: &VetKey,
) -> Result<String, String> {
    // 1. Decode hex to bytes
    let encrypted_data = hex::decode(encrypted_hex).map_err(|_| CIPHERTEXT_ERROR)?;

    // 2. Deserialize the ciphertext
    let ibe_ciphertext =
        IbeCiphertext::deserialize(&encrypted_data).map_err(|_| CIPHERTEXT_ERROR)?;

    // 3. Decrypt the ciphertext
    let decrypted_bytes = ibe_ciphertext
        .decrypt(ibe_decryption_key)
        .map_err(|_| CIPHERTEXT_ERROR)?;

    // 4. Decode back to metadata
    let (metadata,): (String,) = candid::decode_args(&decrypted_bytes).map_err(|_| DECODE_ERROR)?;

    Ok(metadata)
}

/// Decrypts metadata using wallet-specific VetKeys.
///
/// Retrieves the IBE decryption key for the specified wallet and decrypts
/// the hex-encoded metadata data.
///
/// # Arguments
///
/// * `encrypted_hex` - The hex-encoded encrypted metadata data.
/// * `wallet_id` - The wallet identifier used to retrieve the decryption key.
///
/// # Returns
///
/// * `Result<String, String>` - The decrypted metadata string or error message.
pub async fn decrypt_metadata_with_vetkeys(
    encrypted_hex: &str,
    wallet_id: &str,
) -> Result<String, String> {
    let ibe_decryption_key = get_wallet_decryption_key(wallet_id).await?;
    decrypt_single_metadata_hex(encrypted_hex, &ibe_decryption_key).await
}


/// Decrypts complete wallet data including signers, message queue, and metadata.
///
/// Retrieves the IBE decryption key for the specified wallet and decrypts all
/// encrypted components to reconstruct the wallet with decrypted data.
///
/// # Arguments
///
/// * `encrypted_signers` - Vector of hex-encoded encrypted signer principals.
/// * `threshold` - The signing threshold for the wallet.
/// * `encrypted_message_queue` - Vector of tuples containing encrypted message keys and their associated encrypted signers.
/// * `encrypted_metadata` - HashMap mapping encrypted message keys to encrypted metadata values.
/// * `wallet_id` - The wallet identifier used to retrieve the decryption key.
///
/// # Returns
///
/// * `Result<Wallet, String>` - The reconstructed wallet with decrypted data or error message.
pub async fn decrypt_wallet_data(
    encrypted_signers: &Vec<String>,
    threshold: &u8,
    encrypted_message_queue: &Vec<(Vec<u8>, Vec<String>)>,
    encrypted_metadata: &HashMap<Vec<u8>, String>,
    wallet_id: &str,
) -> Result<Wallet, String> {
    // 1. Get decryption key
    let ibe_decryption_key = get_wallet_decryption_key(wallet_id).await?;

    // 2. Decrypt signers + create signer mapping
    let mut decrypted_signers = HashSet::new();
    let mut signer_mapping = HashMap::new(); // encrypted_string -> Principal

    for encrypted_signer in encrypted_signers {
        let principal = decrypt_single_principal_hex(encrypted_signer, &ibe_decryption_key).await?;
        decrypted_signers.insert(principal.to_text());
        signer_mapping.insert(encrypted_signer.clone(), principal.to_text());
    }

    // 3. Decrypt message_queue + create message mapping
    let mut decrypted_message_queue = HashMap::new();
    let mut message_mapping = HashMap::new(); // encrypted_bytes -> decrypted_bytes

    for (encrypted_msg_key, encrypted_signers_vec) in encrypted_message_queue {
        // Decrypt message key
        let decrypted_msg =
            decrypt_single_message_hex(&hex::encode(encrypted_msg_key), &ibe_decryption_key)
                .await?;

        message_mapping.insert(encrypted_msg_key.clone(), decrypted_msg.clone());

        // Map signers using signer_mapping
        let mut mapped_principals = Vec::new();
        for encrypted_signer in encrypted_signers_vec {
            if let Some(principal) = signer_mapping.get(encrypted_signer) {
                mapped_principals.push(principal.clone());
            }
        }

        decrypted_message_queue.insert(decrypted_msg, mapped_principals);
    }

    // 4. Decrypt metadata - using message_mapping
    let mut decrypted_metadata = HashMap::new();
    for (encrypted_msg_key, encrypted_metadata_value) in encrypted_metadata {
        if let Some(decrypted_msg) = message_mapping.get(encrypted_msg_key) {
            // Only decrypt metadata value
            let decrypted_meta =
                decrypt_single_metadata_hex(encrypted_metadata_value, &ibe_decryption_key).await?;
            decrypted_metadata.insert(decrypted_msg.clone(), decrypted_meta);
        }
    }

    Ok(Wallet::new_with_data(
        decrypted_signers,
        *threshold,
        decrypted_message_queue,
        decrypted_metadata,
    ))
}
