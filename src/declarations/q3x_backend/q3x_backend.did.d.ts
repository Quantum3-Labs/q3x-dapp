import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export type Result = { 'Ok' : null } |
  { 'Err' : string };
export type Result_1 = { 'Ok' : string } |
  { 'Err' : string };
export type Result_2 = { 'Ok' : number } |
  { 'Err' : string };
export type Result_3 = { 'Ok' : Array<string> } |
  { 'Err' : string };
export type Result_4 = { 'Ok' : Array<[string, Array<string>]> } |
  { 'Err' : string };
export type Result_5 = { 'Ok' : boolean } |
  { 'Err' : string };
export interface Wallet {
  'threshold' : number,
  'metadata' : Array<[Uint8Array | number[], string]>,
  'signers' : Array<string>,
  'message_queue' : Array<[Uint8Array | number[], Array<string>]>,
}
export interface _SERVICE {
  /**
   * Add metadata to a message in the wallet.
   * 
   * * `message` - The message as a `Vec<u8>`.
   * * `metadata` - The metadata as a `String`.
   * * `caller` - The `Principal` of the caller.
   * 
   * Returns `Result<(), String>` indicating success or the type of failure.
   */
  'add_metadata' : ActorMethod<[string, string, string], Result>,
  /**
   * Proposes adding a new signer to the wallet.
   * 
   * # Arguments
   * 
   * * `wallet_id` - The wallet's unique identifier.
   * * `new_signer` - The Principal of the new signer to add.
   * 
   * # Returns
   * 
   * * `Result<(), String>` - Result indicating success or an error message.
   */
  'add_signer' : ActorMethod<[string, Principal], Result_1>,
  /**
   * Approves a message for signing in the wallet.
   * 
   * # Arguments
   * 
   * * `wallet_id` - The wallet's unique identifier.
   * * `msg` - The message to be approved, in hexadecimal format.
   * 
   * # Returns
   * 
   * * `Result<u8, String>` - The number of signatures or an error message.
   */
  'approve' : ActorMethod<[string, string], Result_2>,
  /**
   * Checks if a message can be signed by the wallet.
   * 
   * # Arguments
   * 
   * * `wallet_id` - The wallet's unique identifier.
   * * `msg` - The message to be checked, in hexadecimal format.
   * 
   * # Returns
   * 
   * * `bool` - True if the message can be signed, otherwise false.
   */
  'can_sign' : ActorMethod<[string, string], boolean>,
  /**
   * Creates a new wallet.
   * 
   * # Arguments
   * 
   * * `wallet_id` - Unique identifier for the wallet as a String.
   * * `signers` - A list of Principals representing the signers of the wallet.
   * * `threshold` - The threshold number of signers required for a transaction.
   * 
   * # Returns
   * 
   * * `Result<(), String>` - Result indicating success or an error message.
   */
  'create_wallet' : ActorMethod<[string, Array<Principal>, number], Result>,
  /**
   * Retrieves all messages that can be signed for a given wallet.
   * 
   * # Arguments
   * 
   * * `wallet_id` - The wallet's unique identifier.
   * 
   * # Returns
   * 
   * * `Vec<Vec<u8>>` - A list of messages that can be signed.
   */
  'get_messages_to_sign' : ActorMethod<[string], Result_3>,
  /**
   * Retrieves all messages that have been proposed along with their signers for a given wallet.
   * 
   * # Arguments
   * 
   * * `wallet_id` - The wallet's unique identifier.
   * 
   * # Returns
   * 
   * * `Vec<(Vec<u8>, Vec<Principal>)>` - A list of tuples containing messages and their signers.
   */
  'get_messages_with_signers' : ActorMethod<[string], Result_4>,
  /**
   * Get the metadata associated with a message in the wallet.
   * 
   * * `message` - The message as a `Vec<u8>`.
   * 
   * Returns `Option<&String>` containing the metadata if it exists.
   */
  'get_metadata' : ActorMethod<[string, string], Result_1>,
  /**
   * Retrieves all messages that have been proposed for a given wallet.
   * 
   * # Arguments
   * 
   * * `wallet_id` - The wallet's unique identifier.
   * 
   * # Returns
   * 
   * * `Vec<Vec<u8>>` - A list of messages that have been proposed.
   */
  'get_proposed_messages' : ActorMethod<[string], Result_3>,
  /**
   * Retrieves a wallet by its ID.
   * 
   * # Arguments
   * 
   * * `wallet_id` - The unique identifier for the wallet as a String.
   * 
   * # Returns
   * 
   * * `Option<Wallet>` - The wallet if found, otherwise None.
   */
  'get_wallet' : ActorMethod<[string], [] | [Wallet]>,
  /**
   * Retrieves all wallets associated with a given principal.
   * 
   * # Arguments
   * 
   * * `principal` - The principal to retrieve wallets for.
   * 
   * # Returns
   * 
   * * `Vec<String>` - A list of wallet IDs associated with the principal.
   */
  'get_wallets_for_principal' : ActorMethod<[Principal], Array<string>>,
  /**
   * Proposes a message to be signed by the wallet.
   * 
   * # Arguments
   * 
   * * `wallet_id` - The wallet's unique identifier.
   * * `msg` - The message to be proposed, in hexadecimal format.
   * 
   * # Returns
   * 
   * * `Result<(), String>` - Result indicating success or an error message.
   */
  'propose' : ActorMethod<[string, string], Result>,
  /**
   * Proposes a message and adds metadata in one call.
   * 
   * # Arguments
   * 
   * * `wallet_id` - The wallet's unique identifier.
   * * `msg` - The message to be proposed, in hexadecimal format.
   * * `metadata` - The metadata to be added to the message.
   * 
   * # Returns
   * 
   * * `Result<(), String>` - Result indicating success or an error message.
   */
  'propose_with_metadata' : ActorMethod<[string, string, string], Result>,
  /**
   * Proposes removing a signer from the wallet.
   * 
   * # Arguments
   * 
   * * `wallet_id` - The wallet's unique identifier.
   * * `signer_to_remove` - The Principal of the signer to remove.
   * 
   * # Returns
   * 
   * * `Result<(), String>` - Result indicating success or an error message.
   */
  'remove_signer' : ActorMethod<[string, Principal], Result_1>,
  /**
   * Proposes setting a new threshold for the wallet.
   * 
   * # Arguments
   * 
   * * `wallet_id` - The wallet's unique identifier.
   * * `new_threshold` - The new threshold value to set.
   * 
   * # Returns
   * 
   * * `Result<String, String>` - Result indicating success or an error message.
   */
  'set_threshold' : ActorMethod<[string, number], Result_1>,
  /**
   * Signs a message using the wallet.
   * 
   * # Arguments
   * 
   * * `wallet_id` - The wallet's unique identifier.
   * * `msg` - The message to be signed, in hexadecimal format.
   * 
   * # Returns
   * 
   * * `Result<String, String>` - The signature in hexadecimal format or an error message.
   */
  'sign' : ActorMethod<[string, string], Result_1>,
  'transfer' : ActorMethod<[string, bigint, Principal], Result_1>,
  /**
   * Verifies a signature for a given message and wallet.
   * 
   * # Arguments
   * 
   * * `wallet_id` - The wallet's unique identifier.
   * * `message` - The message associated with the signature, in hexadecimal format.
   * * `signature` - The signature to be verified, in hexadecimal format.
   * 
   * # Returns
   * 
   * * `Result<bool, String>` - True if the signature is valid, otherwise an error message.
   */
  'verify_signature' : ActorMethod<[string, string, string], Result_5>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
