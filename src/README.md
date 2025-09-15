# Q3x backend, ICP Ledger

Q3x backend is a canister that supports multisig wallet and transfer ICP from its account to other accounts. It uses the ledger canister.

## Architecture

The sample code revolves around one core transfer function which takes as input the amount of ICP to transfer, the account (and optionally the subaccount) to which to transfer ICP and returns either success or an error in case e.g. The Q3x backend canister doesn’t have enough ICP to do the transfer. In case of success, a unique identifier of the transaction is returned. This identifier will be stored in the memo of the transaction in the ledger.

This sample will use the Rust variant.

## Prerequisites

- [x] Install the [IC
  SDK](https://internetcomputer.org/docs/current/developer-docs/getting-started/install). For local testing, `dfx >= 0.22.0` is required.

## Step 1: Setup project environment

Start a local instance of the replica and create a new project with the commands:

```bash
dfx start --clean
```

### Step 2: Determine ledger file locations

The URL for the ledger Wasm module is `https://github.com/dfinity/ic/releases/download/ledger-suite-icp-2025-07-04/ledger-canister_notify-method.wasm.gz`.

The URL for the ledger.did file is `https://github.com/dfinity/ic/releases/download/ledger-suite-icp-2025-07-04/ledger.did`.

## Step 3: Configure the `dfx.json` file to use the ledger

Replace its contents with this but adapt the URLs to be the ones you determined in step 2:

```json
{
    "canisters": {
        "q3x_backend": {
            "candid": "src/q3x_backend/q3x_backend.did",
            "package": "q3x_backend",
            "type": "rust"
        },
        "icp_ledger_canister": {
            "type": "custom",
            "candid": "https://github.com/dfinity/ic/releases/download/ledger-suite-icp-2025-07-04/ledger.did",
            "wasm": "https://github.com/dfinity/ic/releases/download/ledger-suite-icp-2025-07-04/ledger-canister_notify-method.wasm.gz",
            "remote": {
                "id": {
                    "ic": "ryjl3-tyaaa-aaaaa-aaaba-cai"
                }
            }
        },
        "specified_id": "ryjl3-tyaaa-aaaaa-aaaba-cai"
    },
    "defaults": {
        "build": {
            "args": "",
            "packtool": ""
        }
    },
    "output_env_file": ".env",
    "version": 1
}
```

## Step 4: Create a new identity that will work as a minting account

```bash
dfx identity new minter --storage-mode plaintext
dfx identity use minter
export MINTER_ACCOUNT_ID=$(dfx ledger account-id)
```

> [!IMPORTANT]
> Transfers from the minting account will create Mint transactions. Transfers to the minting account will create Burn transactions.

## Step 5: Switch back to your default identity and record its ledger account identifier

```bash
dfx identity use default
export DEFAULT_ACCOUNT_ID=$(dfx ledger account-id)
```

## Step 6: Deploy the ledger canister to your network

Take a moment to read the details of the call made below. Not only are you deploying the ICP ledger canister, you are also:

- Deploying the canister to the same canister ID as the mainnet ledger canister. This is to make it easier to switch between local and mainnet deployments and set in `dfx.json` using `specified_id`.
- Setting the minting account to the account identifier you saved in a previous step (MINTER_ACCOUNT_ID).
- Minting 100 ICP tokens to the DEFAULT_ACCOUNT_ID (1 ICP is equal to 10^8 e8s, hence the name).
- Setting the transfer fee to 0.0001 ICP.
- Naming the token Local ICP / LICP

```bash
dfx deploy icp_ledger_canister --argument "
  (variant {
    Init = record {
      minting_account = \"$MINTER_ACCOUNT_ID\";
      initial_values = vec {
        record {
          \"$DEFAULT_ACCOUNT_ID\";
          record {
            e8s = 10_000_000_000 : nat64;
          };
        };
      };
      send_whitelist = vec {};
      transfer_fee = opt record {
        e8s = 10_000 : nat64;
      };
      token_symbol = opt \"LICP\";
      token_name = opt \"Local ICP\";
    }
  })
"
```

If successful, the output should be:

```bash
Deployed canisters.
URLs:
  Backend canister via Candid interface:
    icp_ledger_canister: http://127.0.0.1:4943/?canisterId=bnz7o-iuaaa-aaaaa-qaaaa-cai&id=ryjl3-tyaaa-aaaaa-aaaba-cai
```

## Step 7: Verify that the ledger canister is healthy and working as expected

```bash
dfx ledger balance $DEFAULT_ACCOUNT_ID
```

The output should be:

```bash
100.00000000 ICP
```

## Step 8: Deploy Q3x backend canister

```bash
generate-did q3x_backend && dfx deploy q3x_backend
```

## Step 9: Determine out the address of q3x backend canister

```bash
Q3X_BACKEND_ACCOUNT_ID="$(dfx ledger account-id --of-canister q3x_backend)"
Q3X_BACKEND_ACCOUNT_ID_BYTES="$(python3 -c 'print("vec{" + ";".join([str(b) for b in bytes.fromhex("'$Q3X_BACKEND_ACCOUNT_ID'")]) + "}")')"
```

## Step 10: Transfer funds to q3x backend canister

> [!TIP]
> Make sure that you are using the default `dfx` account that we minted tokens to in step 6 for the following steps.

Check the balance of q3x backend canister. It should be 0.00000000 ICP.

```bash
dfx ledger balance $Q3X_BACKEND_ACCOUNT_ID
```

Make the following call to transfer funds from the default account to the q3x backend canister:

```bash
dfx canister call icp_ledger_canister transfer "(record { to = ${Q3X_BACKEND_ACCOUNT_ID_BYTES}; memo = 1; amount = record { e8s = 5_00_000_000 }; fee = record { e8s = 10_000 }; })"
```

If successful, the output should be:

```bash
(variant { Ok = 1 : nat64 })
```

Check the balance of the canister. It should be 5.00000000 ICP.

```bash
dfx ledger balance $Q3X_BACKEND_ACCOUNT_ID
```

## Create multisig wallet

```bash
export WalletId="wallet-1"
# Default identity principal
export Signer1="$(dfx identity get-principal)"
# Minter identity principal
export Signer2="$(dfx identity get-principal --identity minter)"

dfx canister call q3x_backend create_wallet "(\"${WalletId}\", vec{ principal \"${Signer1}\"; principal \"${Signer2}\"}, 1)"
```

If successful, the output should be:

```bash
(variant { Ok })
```

Check the multisig wallet info

```bash
dfx canister call q3x_backend get_wallet '("wallet-1")'
```

## Propose transfer funds to default account

```bash
dfx canister call q3x_backend transfer "(\"${WalletId}\", 100_000_000, principal \"${Signer1}\")"
```

If successful, the output should be:

```bash
(
  variant {
    Ok = "hash_message"
  },
)
```

## Approve proposal

Copy the hash message from the output.

```bash
export HashMessage="hash_message" # 5452414e534645523a3a3130303030303030303a3a3535736b642d7a3633356d2d6c3478336b2d6e75726c612d776835346c2d78687772332d6c617462732d75617276662d6966647a6f2d77716166662d797165
dfx canister call q3x_backend approve "(\"${WalletId}\", \"${HashMessage}\")"
```

## Sign/execute proposal

Check default account balance. It should be 0.00000000 ICP.

```bash
dfx ledger balance $DEFAULT_ACCOUNT_ID
```

Execute the proposal.

```bash
dfx canister call q3x_backend sign "(\"${WalletId}\", \"${HashMessage}\")"
```

Check default account balance. It should be around 96 ICP.
