# Simple Blockchain implementation in Rust

A lightweight, educational blockchain node written in Rust. It demonstrates core distributed ledger concepts including Proof of Work, P2P synchronization, and cryptographic transaction signing.

## Features
- **SHA-256 Hashing**: Secure block and transaction hashing.
- **Proof of Work (PoW)**: Mining mechanism with configurable difficulty.
- **P2P Network Sync**: TCP-based peer-to-peer chain synchronization.
- **ECDSA Signatures**: Transaction signing and verification using `secp256k1`.
- **JSON Serialization**: State serialization for peer data transfer.
- **Unit Tests**: Comprehensive test coverage for mining, keys, and transactions.

## How to Run
Ensure you have Rust installed. Clone the repository and use the following commands:

```bash
# Run the first node on port 8080
cargo run -- 8080

# In a new terminal, run the second node on port 8081, syncing with the first node
cargo run -- 8081 8080

# Run unit tests
cargo test
```

## Example Output

**Node 1 (`cargo run -- 8080`)**:
```text
valid = true
after tamper = false
Starting node on port 8080...
Listening on 127.0.0.1:8080
```

**Node 2 (`cargo run -- 8081 8080`)**:
```text
valid = true
after tamper = false
Starting node on port 8081...
Listening on 127.0.0.1:8081
Received chain from peer. Length: 4
Peer chain is longer! Replacing ours.
```

## Technologies & Crates
- **`secp256k1`**: For generating keypairs, signing, and verifying ECDSA transactions.
- **`tokio`**: Asynchronous runtime for handling the TCP server and P2P networking.
- **`serde` & `serde_json`**: For serializing and deserializing blocks and the blockchain state.
- **`hex`**: For encoding SHA-256 hash byte arrays into readable hex strings.
- **`rand`**: For secure random number generation during keypair creation.