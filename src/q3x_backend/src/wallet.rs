use candid::{CandidType, Principal};
use std::collections::{HashMap, HashSet};

use ic_ledger_types::{
    AccountIdentifier, BlockIndex, Memo, Subaccount, Tokens, DEFAULT_SUBACCOUNT,
    MAINNET_LEDGER_CANISTER_ID,
};

use serde::{Deserialize, Serialize};

use crate::privacy::{
    decrypt_messages_with_vetkeys, decrypt_metadata_with_vetkeys, decrypt_wallet_data,
    encrypt_metadata_with_vetkeys, encrypt_principal_and_message_with_vetkeys,
    encrypt_principals_with_vetkeys,
};

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct TransferArgs {
    pub(crate) amount: Tokens,
    pub(crate) to_principal: Principal,
    pub(crate) to_subaccount: Option<Subaccount>,
}
#[derive(Debug, PartialEq)]
pub enum WalletError {
    /// Represents an error when the signature provided is invalid.
    InvalidSignature,
    /// Error when a message is already queued for signing.
    MsgAlreadyQueued,
    /// Error when message is sign by same signer again.
    MsgAlreadySignedBySigner,
    /// Error when a message is not found in the queue.
    MsgNotQueued,
    /// Error when there are not enough signers to meet the threshold.
    NotEnoughSigners,
    /// Error when encryption fails
    EncryptionError,
}

/// A trait defining the behaviors of a MultiSignature Wallet.
pub trait MultiSignatureWallet {
    /// Add a new signer to the wallet.
    ///
    /// * `signer` - The `Principal` of the signer to add.
    /// * `wallet_id` - The ID of the wallet.
    async fn add_signer(&mut self, signer: Principal, wallet_id: &str) -> Result<(), String>;

    /// Add a new signer to the wallet.
    ///
    /// * `signer` - The `Principal - hexString` of the signer to add.
    fn add_signer_principal_hex(&mut self, signer: String);

    /// Remove an existing signer from the wallet.
    ///
    /// * `signer` - The `Principal` of the signer to remove.
    /// * `wallet_id` - The ID of the wallet.
    async fn remove_signer(&mut self, signer: Principal, wallet_id: &str) -> Result<(), String>;

    /// Get a list of all current signers of the wallet.
    ///
    /// Returns a `Vec<Principal>` containing the principals of all signers.
    fn get_signers(&self) -> Vec<String>;

    /// Set the default threshold for signing.
    ///
    /// * `threshold` - The threshold as a `u8` value.
    ///
    /// Returns `Result<(), WalletError>` indicating success or the type of failure.
    fn set_default_threshold(&mut self, threshold: u8) -> Result<(), WalletError>;

    /// Transfer tokens to a principal.
    ///
    /// * `args` - The `TransferArgs` struct containing the amount, to_principal, and to_subaccount.
    ///
    /// Returns `Result<BlockIndex, String>` indicating success or the type of failure.
    async fn transfer(&self, args: TransferArgs) -> Result<BlockIndex, String>;

    /// Check if a given `Principal` is a signer in the wallet.
    ///
    /// * `wallet_id` - The ID of the wallet.
    ///
    /// Returns `bool` indicating whether the signer is present.
    async fn has_signer(&self, wallet_id: &str) -> bool;

    /// Check if a given `Principal - encrypted_data` is a signer in the wallet.
    ///
    /// * `encrypted_signer` - The `Principal - encrypted_data` to check.
    ///
    /// Returns `bool` indicating whether the signer is present.
    fn has_encrypted_signer(&self, encrypted_signer: &str) -> bool;

    /// Get the current default threshold for signing.
    ///
    /// Returns the threshold as a `u8` value.
    fn get_default_threshold(&self) -> u8;

    /// Propose a new message for signing.
    ///
    /// * `caller` - The `Principal` proposing the message.
    /// * `msg` - The message as a `Vec<u8>`.
    /// * `wallet_id` - The ID of the wallet.
    ///
    /// Returns `Result<(), WalletError>` indicating success or the type of failure.
    async fn propose_message(&mut self, msg: Vec<u8>, wallet_id: &str) -> Result<(), WalletError>;

    /// Check if a message can be signed according to the current rules.
    ///
    /// * `msg` - A reference to the message as a `Vec<u8>`.
    ///
    /// Returns `bool` indicating whether the message can be signed.
    fn can_sign(&self, msg: &Vec<u8>) -> bool;

    /// Approve a message with a signer's consent.
    ///
    /// * `msg` - The message as a `Vec<u8>`.
    /// * `wallet_id` - The ID of the wallet.
    ///
    /// Returns `Result<u8, WalletError>` indicating the number of approvals or the type of failure.
    async fn approve(&mut self, msg: Vec<u8>, wallet_id: &str) -> Result<u8, WalletError>;

    /// Returns all messages that can be signed.
    ///
    /// * `wallet_id` - The ID of the wallet.
    ///
    /// Returns a `Vec<Vec<u8>>` containing the messages that can be signed.
    async fn get_messages_to_sign(&self, wallet_id: &str) -> Result<Vec<Vec<u8>>, String>;

    /// Returns all messages that have been proposed.
    ///
    /// * `wallet_id` - The ID of the wallet.
    ///
    /// Returns a `Vec<Vec<u8>>` containing the messages that have been proposed.
    async fn get_proposed_messages(&self, wallet_id: &str) -> Result<Vec<Vec<u8>>, String>;

    /// Returns all messages that have been proposed with their signers.
    ///
    /// * `wallet_id` - The ID of the wallet.
    ///
    /// Returns a `Vec<(Vec<u8>, Vec<Principal>)>` containing the messages that have been proposed with their signers.
    async fn get_messages_with_signers(
        &self,
        wallet_id: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<String>)>, String>;

    /// Returns all encrypted messages that have been proposed with their signers.
    ///
    /// Returns a `Vec<(Vec<u8>, Vec<Principal>)>` containing the messages that have been proposed with their signers.
    fn get_encrypted_messages_with_signers(&self) -> Vec<(Vec<u8>, Vec<String>)>;

    /// Add metadata to a message in the wallet.
    ///
    /// * `message` - The message as a `Vec<u8>`.
    /// * `metadata` - The metadata as a `String`.
    /// * `wallet_id` - The ID of the wallet.
    ///
    /// Returns `Result<(), String>` indicating success or the type of failure.
    async fn add_metadata(
        &mut self,
        message: Vec<u8>,
        metadata: String,
        wallet_id: &str,
    ) -> Result<(), String>;

    /// Get the metadata associated with a message in the wallet.
    ///
    /// * `message` - The message as a `Vec<u8>`.
    /// * `wallet_id` - The ID of the wallet.
    ///
    /// Returns `Option<&String>` containing the metadata if it exists.
    async fn get_metadata(&self, message: Vec<u8>, wallet_id: &str) -> Option<String>;

    /// Get all the metadata associated with wallet.
    /// Returns `HashMap<Vec<u8>, String>` containing all the metadata.
    fn get_all_metadata(&self) -> HashMap<Vec<u8>, String>;

    /// Remove a message and its metadata from the wallet.
    ///
    /// * `msg` - The message as a `Vec<u8>`.
    ///
    /// Returns `Result<(), String>` indicating success or the type of failure.
    async fn remove_message_and_metadata(
        &mut self,
        msg: Vec<u8>,
        wallet_id: &str,
    ) -> Result<(), String>;
}

#[derive(Clone, Debug, CandidType, Deserialize, Default)]
pub struct Wallet {
    /// A set of signers for the wallet, represented by their `Principal` hex string.
    signers: HashSet<String>,
    /// The threshold number of signers required for certain actions.
    threshold: u8,
    /// A map tracking messages and the list of signers (hex string) who have already signed them.
    message_queue: HashMap<Vec<u8>, Vec<String>>,
    /// A map tracking messages and their metadata.
    metadata: HashMap<Vec<u8>, String>,
}

impl Wallet {
    pub fn new_with_data(
        signers: HashSet<String>,
        threshold: u8,
        message_queue: HashMap<Vec<u8>, Vec<String>>,
        metadata: HashMap<Vec<u8>, String>,
    ) -> Self {
        Wallet {
            signers,
            threshold,
            message_queue,
            metadata,
        }
    }
}

impl MultiSignatureWallet for Wallet {
    async fn add_signer(&mut self, signer: Principal, wallet_id: &str) -> Result<(), String> {
        let encrypted_array = encrypt_principals_with_vetkeys(&[signer], wallet_id).await?;
        let encrypted_hex = encrypted_array
            .into_iter()
            .next()
            .ok_or("Failed to encrypt signer")?;
        self.signers.insert(encrypted_hex);
        Ok(())
    }

    fn add_signer_principal_hex(&mut self, signer: String) {
        self.signers.insert(signer);
    }

    async fn remove_signer(&mut self, signer: Principal, wallet_id: &str) -> Result<(), String> {
        let encrypted_array = encrypt_principals_with_vetkeys(&[signer], wallet_id).await?;
        let encrypted_hex = encrypted_array
            .into_iter()
            .next()
            .ok_or("Failed to encrypt signer")?;
        self.signers.remove(&encrypted_hex);
        Ok(())
    }

    fn get_signers(&self) -> Vec<String> {
        self.signers.iter().cloned().collect()
    }

    fn set_default_threshold(&mut self, threshold: u8) -> Result<(), WalletError> {
        if self.signers.len() < threshold as usize {
            return Err(WalletError::NotEnoughSigners);
        }
        self.threshold = threshold;
        Ok(())
    }

    // transfer icp token
    async fn transfer(&self, args: TransferArgs) -> Result<BlockIndex, String> {
        ic_cdk::println!(
            "Transferring {} tokens to principal {} subaccount {:?}",
            &args.amount,
            &args.to_principal,
            &args.to_subaccount
        );
        let to_subaccount = args.to_subaccount.unwrap_or(DEFAULT_SUBACCOUNT);
        let transfer_args = ic_ledger_types::TransferArgs {
            memo: Memo(0),
            amount: args.amount,
            fee: Tokens::from_e8s(10_000),
            // The subaccount of the account identifier that will be used to withdraw tokens and send them
            // to another account identifier. If set to None then the default subaccount will be used.
            // See the [Ledger doc](https://internetcomputer.org/docs/current/developer-docs/integrations/ledger/#accounts).
            from_subaccount: None,
            to: AccountIdentifier::new(&args.to_principal, &to_subaccount),
            created_at_time: None,
        };
        ic_ledger_types::transfer(MAINNET_LEDGER_CANISTER_ID, &transfer_args)
            .await
            .map_err(|e| format!("failed to call ledger: {e:?}"))?
            .map_err(|e| format!("ledger transfer error {e:?}"))
    }

    async fn has_signer(&self, wallet_id: &str) -> bool {
        let signer = ic_cdk::api::msg_caller();
        if let Ok(encrypted_array) = encrypt_principals_with_vetkeys(&[signer], wallet_id).await {
            if let Some(encrypted_hex) = encrypted_array.into_iter().next() {
                return self.signers.contains(&encrypted_hex);
            }
        }
        false
    }

    fn has_encrypted_signer(&self, encrypted_signer: &str) -> bool {
        self.signers.contains(encrypted_signer)
    }

    fn get_default_threshold(&self) -> u8 {
        self.threshold
    }

    async fn propose_message(&mut self, msg: Vec<u8>, wallet_id: &str) -> Result<(), WalletError> {
        let signer = ic_cdk::api::msg_caller();
        let (encrypted_principal, encrypted_message) =
            encrypt_principal_and_message_with_vetkeys(signer, &msg, &wallet_id)
                .await
                .map_err(|_| WalletError::EncryptionError)?;

        if !self.has_encrypted_signer(&encrypted_principal) {
            return Err(WalletError::InvalidSignature);
        }

        if self.message_queue.contains_key(&encrypted_message) {
            return Err(WalletError::MsgAlreadyQueued);
        }

        self.message_queue
            .insert(encrypted_message.clone(), Vec::new());

        Ok(())
    }

    fn can_sign(&self, encrypted_msg: &Vec<u8>) -> bool {
        if !self.message_queue.contains_key(encrypted_msg) {
            return false;
        }
        self.message_queue[encrypted_msg].len() >= self.threshold as usize
    }

    async fn approve(&mut self, msg: Vec<u8>, wallet_id: &str) -> Result<u8, WalletError> {
        let signer = ic_cdk::api::msg_caller();
        let (encrypted_principal, encrypted_message) =
            encrypt_principal_and_message_with_vetkeys(signer, &msg, &wallet_id)
                .await
                .map_err(|_| WalletError::EncryptionError)?;

        if !self.message_queue.contains_key(&encrypted_message) {
            return Err(WalletError::MsgNotQueued);
        }
        if !self.has_encrypted_signer(&encrypted_principal) {
            return Err(WalletError::InvalidSignature);
        }

        let queue: &mut Vec<String> = self.message_queue.get_mut(&encrypted_message).unwrap();

        if queue.contains(&encrypted_principal) {
            return Err(WalletError::MsgAlreadySignedBySigner);
        }

        queue.push(encrypted_principal);

        Ok(queue.len() as u8)
    }

    async fn get_messages_to_sign(&self, wallet_id: &str) -> Result<Vec<Vec<u8>>, String> {
        let messages: Vec<Vec<u8>> = self
            .message_queue
            .iter()
            .filter(|(encrypted_msg, _)| self.can_sign(encrypted_msg))
            .map(|(msg, _)| msg.clone())
            .collect();

        if self.has_signer(wallet_id).await {
            // Authorized - decrypt messages
            let encrypted_hex_list: Vec<String> = messages.iter().map(hex::encode).collect();
            match decrypt_messages_with_vetkeys(&encrypted_hex_list, wallet_id).await {
                Ok(decrypted_messages) => Ok(decrypted_messages),
                Err(_) => Ok(messages), // Fallback to encrypted
            }
        } else {
            // Not authorized - return encrypted messages
            Ok(messages)
        }
    }

    async fn get_proposed_messages(&self, wallet_id: &str) -> Result<Vec<Vec<u8>>, String> {
        let messages: Vec<Vec<u8>> = self.message_queue.keys().cloned().collect();

        if self.has_signer(wallet_id).await {
            // Authorized - decrypt messages
            let encrypted_hex_list: Vec<String> = messages.iter().map(hex::encode).collect();
            match decrypt_messages_with_vetkeys(&encrypted_hex_list, wallet_id).await {
                Ok(decrypted_messages) => Ok(decrypted_messages),
                Err(_) => Ok(messages), // Fallback to encrypted
            }
        } else {
            // Not authorized - return encrypted messages
            Ok(messages)
        }
    }

    async fn get_messages_with_signers(
        &self,
        wallet_id: &str,
    ) -> Result<Vec<(Vec<u8>, Vec<String>)>, String> {
        let messages_with_signers: Vec<(Vec<u8>, Vec<String>)> = self
            .message_queue
            .iter()
            .map(|(msg, signers)| (msg.clone(), signers.clone()))
            .collect();

        if self.has_signer(wallet_id).await {
            // Authorized - decrypt both messages and signers
            match decrypt_wallet_data(
                &self.get_signers(),
                &self.get_default_threshold(),
                &self.get_encrypted_messages_with_signers(),
                &self.get_all_metadata(),
                wallet_id,
            )
            .await
            {
                Ok(decrypted_data) => {
                    // Convert decrypted data back to Vec<(Vec<u8>, Vec<String>)>
                    let mut result = Vec::new();
                    for (decrypted_msg, decrypted_signers) in decrypted_data.message_queue {
                        let signer_strings: Vec<String> = decrypted_signers
                            .into_iter()
                            .map(|p| p.to_string())
                            .collect();
                        result.push((decrypted_msg, signer_strings));
                    }
                    Ok(result)
                }
                Err(_) => Ok(messages_with_signers), // Fallback to encrypted
            }
        } else {
            // Not authorized - return encrypted
            Ok(messages_with_signers)
        }
    }

    fn get_encrypted_messages_with_signers(&self) -> Vec<(Vec<u8>, Vec<String>)> {
        self.message_queue
            .iter()
            .map(|(msg, signers)| (msg.clone(), signers.clone()))
            .collect()
    }

    async fn add_metadata(
        &mut self,
        message: Vec<u8>,
        metadata: String,
        wallet_id: &str,
    ) -> Result<(), String> {
        let signer = ic_cdk::api::msg_caller();
        let (encrypted_principal, encrypted_message) =
            encrypt_principal_and_message_with_vetkeys(signer, &message, &wallet_id)
                .await
                .map_err(|_| "EncryptionError".to_string())?;

        if !self.has_encrypted_signer(&encrypted_principal) {
            return Err("Cannot add metadata: No signer.".to_string());
        }
        if !self.message_queue.contains_key(&encrypted_message) {
            return Err("Cannot add metadata: Message not found.".to_string());
        }
        if self.metadata.contains_key(&encrypted_message) {
            return Err("Metadata already exists for this message".to_string());
        }
        let encrypted_metadata = encrypt_metadata_with_vetkeys(metadata, wallet_id)
            .await
            .map_err(|_| "EncryptionError".to_string())?;
        self.metadata.insert(encrypted_message, encrypted_metadata);
        Ok(())
    }

    async fn get_metadata(&self, message: Vec<u8>, wallet_id: &str) -> Option<String> {
        let signer = ic_cdk::api::msg_caller();

        // Encrypt principal and message
        let (encrypted_principal, encrypted_message) =
            encrypt_principal_and_message_with_vetkeys(signer, &message, &wallet_id)
                .await
                .ok()?;

        // Check if signer is authorized
        if !self.has_encrypted_signer(&encrypted_principal) {
            return None;
        }

        // Get encrypted metadata
        let encrypted_metadata = self.metadata.get(&encrypted_message)?;

        // Decrypt and return metadata
        decrypt_metadata_with_vetkeys(&encrypted_metadata, wallet_id)
            .await
            .ok()
    }

    fn get_all_metadata(&self) -> HashMap<Vec<u8>, String> {
        self.metadata
            .iter()
            .map(|(msg, meta)| (msg.clone(), meta.clone()))
            .collect()
    }

    async fn remove_message_and_metadata(
        &mut self,
        msg: Vec<u8>,
        wallet_id: &str,
    ) -> Result<(), String> {
        let signer = ic_cdk::api::msg_caller();
        let (encrypted_principal, encrypted_message) =
            encrypt_principal_and_message_with_vetkeys(signer, &msg, &wallet_id)
                .await
                .map_err(|_| "EncryptionError".to_string())?;

        // Check if the caller is a signer
        if !self.has_encrypted_signer(&encrypted_principal) {
            return Err("CallerNotSigner".to_string());
        }

        // Remove the message and its metadata
        self.message_queue.remove(&encrypted_message);
        self.metadata.remove(&encrypted_message);

        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use candid::Principal;
//     use std::str::FromStr;

//     #[test]
//     fn test_default_wallet() {
//         let wallet = Wallet::default();
//         assert_eq!(wallet.get_signers().len(), 0);
//         assert_eq!(wallet.get_default_threshold(), 0);
//     }

//     #[test]
//     fn test_add_remove_signer() {
//         let mut wallet = Wallet::default();

//         let signer1 = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         let signer2 = Principal::from_str("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();

//         wallet.add_signer(signer1);
//         wallet.add_signer(signer2);

//         let signers = wallet.get_signers();
//         assert_eq!(signers.len(), 2);
//         assert!(signers.contains(&signer1));
//         assert!(signers.contains(&signer2));

//         wallet.remove_signer(signer1);
//         let signers = wallet.get_signers();
//         assert_eq!(signers.len(), 1);
//         assert!(!signers.contains(&signer1));
//         assert!(signers.contains(&signer2));
//     }

//     #[test]
//     fn test_set_get_default_threshold() {
//         let mut wallet = Wallet::default();

//         assert_eq!(wallet.get_default_threshold(), 0);

//         wallet.add_signer(Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap());
//         let _ = wallet.set_default_threshold(1);
//         assert_eq!(wallet.get_default_threshold(), 1);
//         assert_eq!(
//             wallet.set_default_threshold(2),
//             Err(WalletError::NotEnoughSigners)
//         );
//     }

//     #[test]
//     fn test_propose_message_valid_signature() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         wallet.add_signer(signer);

//         let msg = vec![1, 2, 3];
//         let result = wallet.propose_message(signer, msg);

//         assert!(result.is_ok());
//     }

//     #[test]
//     fn test_propose_message_invalid_signature() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         // Don't add the signer to the wallet.
//         // wallet.add_signer(signer.clone());

//         let msg = vec![1, 2, 3];
//         let result = wallet.propose_message(signer, msg.clone());

//         assert_eq!(result.err(), Some(WalletError::InvalidSignature));
//     }

//     #[test]
//     fn test_propose_message_duplicate_message() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         wallet.add_signer(signer);

//         let msg = vec![1, 2, 3];
//         let _ = wallet.propose_message(signer, msg.clone());

//         // Try proposing the same message again.
//         let result = wallet.propose_message(signer, msg);

//         assert_eq!(result.err(), Some(WalletError::MsgAlreadyQueued));
//     }

//     #[test]
//     fn test_can_sign_threshold_not_met() {
//         let mut wallet = Wallet::default();

//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         wallet.add_signer(signer);
//         let _ = wallet.set_default_threshold(1);

//         let msg = vec![1, 2, 3];
//         let _ = wallet.propose_message(signer, msg.clone());

//         // Threshold is not met, so cannot sign.
//         let can_sign = wallet.can_sign(&msg.clone());

//         assert!(!can_sign);
//     }

//     #[test]
//     fn test_can_sign_message_not_queued() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         wallet.add_signer(signer);

//         let msg = vec![1, 2, 3];

//         // Message is not in the queue, so cannot sign.
//         let can_sign = wallet.can_sign(&msg.clone());

//         assert!(!can_sign);
//     }

//     #[test]
//     fn test_approve_valid_message() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         wallet.add_signer(signer);
//         let _ = wallet.set_default_threshold(1);

//         let msg = vec![1, 2, 3];
//         wallet.propose_message(signer, msg.clone()).unwrap();

//         assert!(!wallet.can_sign(&msg));
//         let result = wallet.approve(msg.clone(), signer);

//         assert!(result.is_ok());
//         assert!(wallet.can_sign(&msg));
//     }

//     #[test]
//     fn test_approve_invalid_message() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         wallet.add_signer(signer);

//         let msg = vec![1, 2, 3];

//         let result = wallet.approve(msg.clone(), signer);

//         assert_eq!(result.err(), Some(WalletError::MsgNotQueued));
//     }

//     #[test]
//     fn test_approve_not_signer() {
//         let mut wallet = Wallet::default();
//         let signer1 = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         let signer2 = Principal::from_str("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
//         let _ = wallet.set_default_threshold(1);
//         wallet.add_signer(signer1);

//         let msg = vec![1, 2, 3];
//         wallet.propose_message(signer1, msg.clone()).unwrap();

//         let result = wallet.approve(msg.clone(), signer2);

//         assert_eq!(result.err(), Some(WalletError::InvalidSignature));
//     }

//     #[test]
//     fn test_has_signer() {
//         let mut wallet = Wallet::default();
//         let signer1 = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         let signer2 = Principal::from_str("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
//         wallet.add_signer(signer1);

//         assert!(wallet.has_signer(signer1));
//         assert!(!wallet.has_signer(signer2));
//     }

//     #[test]
//     fn test_get_messages() {
//         let mut wallet = Wallet::default();
//         let signer1 = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         let signer2 = Principal::from_str("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
//         wallet.add_signer(signer1);
//         wallet.add_signer(signer2);
//         let _ = wallet.set_default_threshold(1);

//         let msg1 = vec![1, 2, 3];
//         let msg2 = vec![4, 5, 6];
//         let msg3 = vec![7, 8, 9];
//         wallet.propose_message(signer1, msg1.clone()).unwrap();
//         wallet.propose_message(signer2, msg2.clone()).unwrap();
//         wallet.propose_message(signer2, msg3.clone()).unwrap();

//         wallet.approve(msg1.clone(), signer1).unwrap();
//         wallet.approve(msg2.clone(), signer2).unwrap();

//         let messages_to_sign = wallet.get_messages_to_sign();

//         assert_eq!(messages_to_sign.len(), 2);
//         assert!(messages_to_sign.contains(&msg1));
//         assert!(messages_to_sign.contains(&msg2));

//         let proposed_messages = wallet.get_proposed_messages();

//         assert_eq!(proposed_messages.len(), 3);

//         let all_messages_with_signers = wallet.get_messages_with_signers();

//         assert_eq!(all_messages_with_signers.len(), 3);
//         // TODO: encrypt signer first
//         assert!(all_messages_with_signers.contains(&(msg1.clone(), vec![signer1.to_string()])));
//         assert!(all_messages_with_signers.contains(&(msg2.clone(), vec![signer2.to_string()])));
//         assert!(all_messages_with_signers.contains(&(msg3.clone(), vec![])));
//     }

//     #[test]
//     fn test_add_metadata_valid() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         wallet.add_signer(signer);

//         let msg = vec![1, 2, 3];
//         let _ = wallet.propose_message(signer, msg.clone());

//         let result = wallet.add_metadata(msg.clone(), "metadata".to_string(), signer);

//         assert!(result.is_ok());
//         assert_eq!(
//             wallet.get_metadata(msg.clone(), signer),
//             Some(&"metadata".to_string())
//         );
//     }

//     #[test]
//     fn test_add_metadata_invalid_message() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         wallet.add_signer(signer);

//         let msg = vec![1, 2, 3];

//         let result = wallet.add_metadata(msg.clone(), "metadata".to_string(), signer);

//         assert_eq!(
//             result.err(),
//             Some("Cannot add metadata: Message not found.".to_string())
//         );
//     }

//     #[test]
//     fn test_add_metadata_invalid_signer() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         let invalid_signer = Principal::from_str("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
//         wallet.add_signer(signer);

//         let msg = vec![1, 2, 3];
//         let _ = wallet.propose_message(signer, msg.clone());

//         let result = wallet.add_metadata(msg.clone(), "metadata".to_string(), invalid_signer);

//         assert_eq!(
//             result.err(),
//             Some("Cannot add metadata: No signer.".to_string())
//         );
//     }

//     #[test]
//     fn test_get_metadata_exists() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         wallet.add_signer(signer);

//         let msg = vec![1, 2, 3];
//         let _ = wallet.propose_message(signer, msg.clone());
//         let _ = wallet.add_metadata(msg.clone(), "metadata".to_string(), signer);

//         let result = wallet.get_metadata(msg.clone(), signer);

//         assert_eq!(result, Some(&"metadata".to_string()));
//     }

//     #[test]
//     fn test_get_metadata_not_exists() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         wallet.add_signer(signer);

//         let msg = vec![1, 2, 3];
//         let _ = wallet.propose_message(signer, msg.clone());

//         let result = wallet.get_metadata(msg.clone(), signer);

//         assert_eq!(result, None);
//     }

//     #[test]
//     fn test_get_metadata_returns_none_if_not_signer() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         let invalid_signer = Principal::from_str("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();
//         wallet.add_signer(signer);

//         let msg = vec![1, 2, 3];
//         let _ = wallet.propose_message(signer, msg.clone());
//         let _ = wallet.add_metadata(msg.clone(), "metadata".to_string(), signer);

//         let result = wallet.get_metadata(msg.clone(), invalid_signer);

//         assert_eq!(result, None);
//     }

//     #[test]
//     fn test_add_metadata_only_once() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         wallet.add_signer(signer);

//         let msg = vec![1, 2, 3];
//         let _ = wallet.propose_message(signer, msg.clone());

//         let result = wallet.add_metadata(msg.clone(), "metadata".to_string(), signer.clone());
//         assert!(result.is_ok());
//         assert_eq!(
//             wallet.get_metadata(msg.clone(), signer),
//             Some(&"metadata".to_string())
//         );

//         // Try to add metadata again to the same message
//         let result = wallet.add_metadata(msg.clone(), "new metadata".to_string(), signer.clone());
//         assert_eq!(
//             result.err(),
//             Some("Metadata already exists for this message".to_string())
//         );
//     }

//     #[test]
//     fn test_remove_message_and_metadata() {
//         let mut wallet = Wallet::default();
//         let signer = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
//         wallet.add_signer(signer);

//         let msg = vec![1, 2, 3];
//         let _ = wallet.propose_message(signer, msg.clone());
//         let _ = wallet.add_metadata(msg.clone(), "metadata".to_string(), signer);

//         assert_eq!(
//             wallet.get_metadata(msg.clone(), signer),
//             Some(&"metadata".to_string())
//         );

//         let result = wallet.remove_message_and_metadata(msg.clone(), signer);

//         assert!(result.is_ok());
//         assert_eq!(wallet.get_metadata(msg.clone(), signer), None);
//         assert!(!wallet.message_queue.contains_key(&msg));
//     }
// }
