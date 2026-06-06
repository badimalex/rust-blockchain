use secp256k1::hashes::{Hash, sha256};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use secp256k1::rand::{self};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

#[derive(Serialize, Deserialize, Debug)]
pub struct Block {
    pub index: u32,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub hash: String,
    pub nonce: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Blockchain {
    pub vec: Vec<Block>,
    pub difficulty: u32,
    pub mempool: Vec<Transaction>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction {
    pub from: PublicKey,
    pub to: PublicKey,
    pub amount: u64,
    pub signature: secp256k1::ecdsa::Signature,
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();

    let (secret_key, public_key) = secp.generate_keypair(&mut rand::rng());

    (secret_key, public_key)
}

pub fn sign_transaction(
    to_public_key: PublicKey,
    amount: u64,
    secret_key: &SecretKey,
) -> Transaction {
    let secp = Secp256k1::new();
    let from_public_key = PublicKey::from_secret_key(&secp, secret_key);

    let message_to_sign = format!("{}{}{}", from_public_key, to_public_key, amount);

    let digest = sha256::Hash::hash(message_to_sign.as_bytes()).to_byte_array();

    let message = Message::from_digest(digest);

    let signature = secp.sign_ecdsa(message, secret_key);

    Transaction {
        from: from_public_key,
        to: to_public_key,
        signature,
        amount,
    }
}

impl Transaction {
    pub fn verify_transaction(&self) -> bool {
        let secp = Secp256k1::new();
        let message_to_sign = format!("{}{}{}", self.from, self.to, self.amount);
        let digest = sha256::Hash::hash(message_to_sign.as_bytes()).to_byte_array();
        let message = Message::from_digest(digest);

        secp.verify_ecdsa(message, &self.signature, &self.from)
            .is_ok()
    }
}

impl Default for Blockchain {
    fn default() -> Self {
        Self::new()
    }
}

impl Blockchain {
    pub fn new() -> Self {
        let timestamp = current_time();
        let difficulty = 2;

        Blockchain {
            difficulty,
            vec: vec![Block::new(0, timestamp, vec![], "0".into(), difficulty)],
            mempool: vec![],
        }
    }

    pub fn add_to_mempool(&mut self, tx: Transaction) -> bool {
        if tx.verify_transaction() {
            self.mempool.push(tx);
            true
        } else {
            false
        }
    }

    pub fn add_block(&mut self) {
        let transactions = std::mem::take(&mut self.mempool);
        let previous_hash = match self.vec.last() {
            Some(block) => block.hash.clone(),
            None => "0".to_string(),
        };
        let timestamp = current_time();
        let index = self.vec.len() as u32;

        let first_block: Block = Block::new(
            index,
            timestamp,
            transactions,
            previous_hash,
            self.difficulty,
        );
        self.vec.push(first_block);
    }

    pub fn is_valid(&self) -> bool {
        if self.vec.is_empty() {
            return false;
        }

        let genesis = &self.vec[0];
        if genesis.index != 0 || genesis.previous_hash != "0" {
            return false;
        }

        let transactions_str = serde_json::to_string(&genesis.transactions).unwrap();
        let right_hash = format!(
            "{}{}{}{}{}",
            genesis.index,
            genesis.timestamp,
            transactions_str,
            genesis.previous_hash,
            genesis.nonce
        );

        if make_hash(&right_hash) != genesis.hash {
            return false;
        }

        if !genesis
            .hash
            .starts_with(&"0".repeat(self.difficulty as usize))
        {
            return false;
        }

        for j in 1..self.vec.len() {
            if self.vec[j].previous_hash != self.vec[j - 1].hash {
                return false;
            }
            let transactions_str = serde_json::to_string(&self.vec[j].transactions).unwrap();
            let right_hash = format!(
                "{}{}{}{}{}",
                self.vec[j].index,
                self.vec[j].timestamp,
                transactions_str,
                self.vec[j].previous_hash,
                self.vec[j].nonce
            );

            if make_hash(&right_hash) != self.vec[j].hash {
                return false;
            }

            if !self.vec[j]
                .hash
                .starts_with(&"0".repeat(self.difficulty as usize))
            {
                return false;
            }
        }
        true
    }
}

impl Block {
    pub fn new(
        index: u32,
        timestamp: u64,
        transactions: Vec<Transaction>,
        previous_hash: String,
        difficulty: u32,
    ) -> Self {
        let (nonce, hash) = mine(
            difficulty as usize,
            index,
            timestamp,
            &transactions,
            &previous_hash,
        );

        Block {
            index,
            timestamp,
            transactions,
            hash,
            previous_hash,
            nonce,
        }
    }
}

fn current_time() -> u64 {
    let start = SystemTime::now();

    start
        .duration_since(UNIX_EPOCH)
        .expect("Time before Unix epoch!")
        .as_secs()
}

fn make_hash(input: &str) -> String {
    let hs = sha256::Hash::hash(input.as_bytes());
    hex::encode(hs.as_byte_array())
}

async fn start_server(port: u16, chain: Arc<Mutex<Blockchain>>) -> std::io::Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

    loop {
        let (socket, addr) = listener.accept().await?;

        let mock_chain = Arc::clone(&chain);

        tokio::spawn(async move {
            if let Err(err) = handle_client(socket, mock_chain).await {
                eprintln!("Error handling client {}: {}", addr, err);
            }
        });
    }
}

async fn sync_with_peer(addr: &str, chain: Arc<Mutex<Blockchain>>) {
    match TcpStream::connect(addr).await {
        Ok(mut stream) => {
            let mut buffer = String::new();

            if stream.read_to_string(&mut buffer).await.is_ok() {
                if let Ok(peer_chain) = serde_json::from_str::<Blockchain>(&buffer) {
                    println!("Received chain from peer. Length: {}", peer_chain.vec.len());

                    let mut lock = chain.lock().await;
                    if peer_chain.vec.len() > lock.vec.len() {
                        println!("Peer chain is longer! Replacing ours.");
                        *lock = peer_chain;
                    } else {
                        println!("Our chain is longer or equal. No changes.");
                    }
                } else {
                    eprintln!("JSON parsing error.");
                }
            } else {
                eprintln!("Error reading from stream");
            }
        }
        Err(e) => {
            eprintln!("Error connecting to peer {}: {}", addr, e);
        }
    }
}

#[tokio::main]
async fn main() {
    let (secret_key_from, _) = generate_keypair();
    let (_, public_key_to) = generate_keypair();
    let mut tx = sign_transaction(public_key_to, 100, &secret_key_from);
    println!("valid = {}", tx.verify_transaction());
    tx.amount = 101;
    println!("after tamper = {}", tx.verify_transaction());

    let args: Vec<String> = std::env::args().collect();

    let server_port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(8080);
    let peer_port: Option<u16> = args.get(2).and_then(|s| s.parse().ok());

    println!("Starting node on port {}...", server_port);

    let chain = Arc::new(Mutex::new(Blockchain::new()));

    if server_port == 8080 {
        let tx1 = sign_transaction(public_key_to, 101, &secret_key_from);
        println!("valid = {}", tx1.verify_transaction());
        let tx2 = sign_transaction(public_key_to, 102, &secret_key_from);
        println!("valid = {}", tx2.verify_transaction());
        let tx3 = sign_transaction(public_key_to, 103, &secret_key_from);
        println!("valid = {}", tx3.verify_transaction());
        let mut lock = chain.lock().await;
        lock.add_to_mempool(tx1);
        lock.add_to_mempool(tx2);
        lock.add_to_mempool(tx3);
    }

    let clone: Arc<Mutex<Blockchain>> = chain.clone();
    tokio::spawn(async move {
        if let Err(err) = start_server(server_port, clone).await {
            eprintln!("Server error on port {}: {}", server_port, err);
        }
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    if let Some(p_port) = peer_port {
        let peer_addr = format!("127.0.0.1:{}", p_port);
        sync_with_peer(&peer_addr, chain.clone()).await;
    }

    println!("Listening on 127.0.0.1:{}", server_port);

    tokio::signal::ctrl_c().await.unwrap();
}

async fn handle_client(
    mut socket: TcpStream,
    chain: Arc<Mutex<Blockchain>>,
) -> Result<(), Box<dyn Error>> {
    let json_data = {
        let guard = chain.lock().await;
        serde_json::to_string(&*guard)?
    };
    socket.write_all(json_data.as_bytes()).await?;

    Ok(())
}

fn mine(
    difficulty: usize,
    index: u32,
    timestamp: u64,
    transactions: &[Transaction],
    previous_hash: &str,
) -> (u64, String) {
    let transactions_str = serde_json::to_string(transactions).unwrap();
    let base = format!(
        "{}{}{}{}",
        index, timestamp, transactions_str, previous_hash
    );
    let mut nonce: u64 = 0;

    loop {
        let data_to_hash = format!("{}{}", base, nonce);
        let hash = make_hash(&data_to_hash);

        if hash.starts_with(&"0".repeat(difficulty)) {
            return (nonce, hash);
        }
        nonce += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_mining_hello_blockchain() {
        let difficulty = [1, 3, 4];
        for &diff in &difficulty {
            // 1. Фиксируем время ДО выполнения функции
            let start = Instant::now();

            let mut bc = Blockchain {
                difficulty: diff,
                vec: vec![],
                mempool: vec![],
            };
            bc.vec
                .push(Block::new(0, current_time(), vec![], "0".into(), diff));
            let (secret_key_from, _) = generate_keypair();
            let (_, public_key_to) = generate_keypair();
            let tx = sign_transaction(public_key_to, 200, &secret_key_from);
            println!("valid = {}", tx.verify_transaction());
            bc.add_to_mempool(tx);

            // 3. Вычисляем прошедшее время
            let elapsed = start.elapsed();

            println!("Difficulty {} generated in {:?}", diff, elapsed);
        }
    }

    #[test]
    fn test_generate_keys() {
        // 1. Initialize a full secp256k1 context with all capabilities
        let secp = Secp256k1::new();

        // 2. Generate a secure, random cryptographic keypair
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::rng());

        println!("Public Key: {}", public_key);
        println!("Secret Key: {}", secret_key.display_secret());
    }

    #[test]
    fn test_transaction_sign_verify() {
        let secp = Secp256k1::new();

        let (from_secret_key, _) = secp.generate_keypair(&mut rand::rng());

        let (_, to_public_key) = secp.generate_keypair(&mut rand::rng());

        let mut transaction = sign_transaction(to_public_key, 100, &from_secret_key);

        let is_valid = transaction.verify_transaction();
        assert!(is_valid);

        transaction.amount = 101;

        assert!(!transaction.verify_transaction());
    }

    #[test]
    fn test_sign_verify() {
        let secp = Secp256k1::new();

        let (secret_key, public_key) = secp.generate_keypair(&mut rand::rng());
        println!("Secret Key: {:?}", secret_key);
        println!("Public Key: {:?}", public_key);

        let original_message = b"send 100 usd";
        let digest = sha256::Hash::hash(original_message).to_byte_array();

        let message = Message::from_digest(digest);

        let signature = secp.sign_ecdsa(message, &secret_key);
        println!(
            "Signature (Compact format): {:?}",
            signature.serialize_compact()
        );

        let is_valid = secp.verify_ecdsa(message, &signature, &public_key).is_ok();
        assert!(is_valid);
        println!("Signature successfully verified! Status: {}", is_valid);

        // another msg

        let original_message2 = b"send 101 usd";
        let digest2 = sha256::Hash::hash(original_message2).to_byte_array();

        // 4. Wrap the digest into a secp256k1 Message object
        let message2 = Message::from_digest(digest2);

        let is_valid = secp.verify_ecdsa(message2, &signature, &public_key).is_ok();
        assert!(!is_valid);
        println!("Verification for tampered message: {}", is_valid);
    }

    #[test]
    fn test_add_to_mempool() {
        let (secret_key_from, _) = generate_keypair();
        let (_, public_key_to) = generate_keypair();

        let tx1 = sign_transaction(public_key_to, 101, &secret_key_from);
        println!("valid 1 = {}", tx1.verify_transaction());
        let tx2 = sign_transaction(public_key_to, 102, &secret_key_from);
        println!("valid 2 = {}", tx2.verify_transaction());
        let mut tx3 = sign_transaction(public_key_to, 103, &secret_key_from);
        tx3.amount = 999;
        println!("valid 3 = {}", tx3.verify_transaction());

        let diff = 4;

        let mut bc = Blockchain {
            difficulty: diff,
            vec: vec![],
            mempool: vec![],
        };
        bc.vec
            .push(Block::new(0, current_time(), vec![], "0".into(), diff));

        bc.add_to_mempool(tx1);
        bc.add_to_mempool(tx2);
        bc.add_to_mempool(tx3);

        bc.add_block();
        let last_block = bc.vec.last().unwrap();

        assert_eq!(last_block.transactions.len(), 2);
    }
}
