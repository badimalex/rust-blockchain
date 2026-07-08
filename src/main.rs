use secp256k1::hashes::{Hash, sha256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use secp256k1::rand::{self};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

const BLOCK_REWARD: u64 = 50;

#[derive(Serialize, Deserialize, Debug)]
pub enum TransactionError {
    SerializationFailed,
    InvalidSignature,
}

#[derive(Serialize)]
struct TransactionPayload<'a> {
    from: String,
    to: String,
    amount: u64,
    fee: u64,
    nonce: u64,
    instruction_data: &'a Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum TransferError {
    SenderNotFound,
    ReceiverNotFound,
    InsufficientFunds,
}

#[derive(Debug)]
pub enum MempoolError {
    InvalidSignature,
    AccountNotFound,
    InvalidNonce,
    InsufficientFunds,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Block {
    pub index: u32,
    pub timestamp: u64,
    pub coinbase: CoinbaseTransaction,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub hash: String,
    pub nonce: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    pub coins: u64,
    pub data: Vec<u8>,
    pub owner: PublicKey,
    pub executable: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Blockchain {
    pub vec: Vec<Block>,
    pub difficulty: u32,
    pub mempool: Vec<Transaction>,
    pub accounts: HashMap<PublicKey, Account>,
    pub faucet_program_id: PublicKey,
    pub notebook_program_id: PublicKey,
    pub nonces: HashMap<PublicKey, u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CoinbaseTransaction {
    pub to: PublicKey,
    pub amount: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction {
    pub from: PublicKey,
    pub to: PublicKey,
    pub amount: u64,
    pub signature: secp256k1::ecdsa::Signature,
    pub instruction_data: Vec<u8>,
    pub fee: u64,
    pub nonce: u64,
}

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();

    let (secret_key, public_key) = secp.generate_keypair(&mut rand::rng());

    (secret_key, public_key)
}

fn create_transaction_message(
    from: &PublicKey,
    to: &PublicKey,
    amount: u64,
    fee: u64,
    nonce: u64,
    data: &Vec<u8>,
) -> Result<Message, TransactionError> {


    let payload = TransactionPayload {

        from: from.to_string(),

        to: to.to_string(),

        amount,

        fee,

        nonce,

        instruction_data:data,
    };


    let serialized =
        serde_json::to_vec(&payload)
            .map_err(|_| TransactionError::SerializationFailed)?;


    let hash =
        sha256::Hash::hash(&serialized)
            .to_byte_array();


    Ok(Message::from_digest(hash))
}

pub fn sign_transaction(
    to_public_key: PublicKey,
    amount: u64,
    instruction_data: Vec<u8>,
    secret_key: &SecretKey,
    fee: u64,
    nonce: u64,
) -> Result<Transaction, TransactionError> {
    let secp = Secp256k1::new();
    let from_public_key = PublicKey::from_secret_key(&secp, secret_key);

    // let instruction_hex = hex::encode(&instruction_data);
    // let message_to_sign = format!(
    //     "{}{}{}{}{}{}",
    //     from_public_key, to_public_key, amount, fee, nonce, instruction_hex
    // );
    let message = create_transaction_message(
        &from_public_key,
        &to_public_key,
        amount,
        fee,
        nonce,
        &instruction_data,
    )?;

    // let digest = sha256::Hash::hash(message.as_bytes()).to_byte_array();

    // let message = Message::from_digest(digest);

    let signature = secp.sign_ecdsa(message, secret_key);

    Ok(Transaction {
        from: from_public_key,
        to: to_public_key,
        signature,
        instruction_data,
        amount,
        fee,
        nonce,
    })
}

impl Transaction {
    pub fn verify_transaction(&self) -> Result<(), TransactionError> {
        let secp = Secp256k1::new();
       
         let message = create_transaction_message(
            &self.from,
            &self.to,
            self.amount,
            self.fee,
            self.nonce,
            &self.instruction_data,
        )?;

       secp.verify_ecdsa(message, &self.signature, &self.from)
        .map_err(|_| TransactionError::InvalidSignature)?;

        Ok(())
    }
}

impl Blockchain {
    pub fn new(
        genesis_pubkey: PublicKey,
        faucet_program_id: PublicKey,
        notebook_program_id: PublicKey,
    ) -> Self {
        let timestamp = current_time();
        let difficulty = 2;
        let mut accounts = HashMap::new();
        accounts.insert(
            genesis_pubkey,
            Account {
                coins: 1000,
                data: vec![],
                owner: genesis_pubkey,
                executable: false,
            },
        );
        let mut nonces = HashMap::new();
        nonces.insert(genesis_pubkey, 0);

        let genesis_coinbase = CoinbaseTransaction {
            to: genesis_pubkey,
            amount: BLOCK_REWARD,
        };

        Blockchain {
            accounts,
            difficulty,
            vec: vec![Block::new(
                0,
                timestamp,
                vec![],
                "0".into(),
                difficulty,
                genesis_coinbase,
            )],
            mempool: vec![],
            faucet_program_id,
            notebook_program_id,
            nonces,
        }
    }

    pub fn deploy_program(&mut self, program_id: PublicKey, code: Vec<u8>) {
        self.accounts.insert(
            program_id,
            Account {
                coins: 0,
                data: code,
                owner: program_id,
                executable: true,
            },
        );
    }

    pub fn create_data_account(&mut self, account_key: PublicKey, program_owner: PublicKey) {
        self.accounts.insert(
            account_key,
            Account {
                coins: 0,
                data: vec![],
                owner: program_owner,
                executable: false,
            },
        );
    }

    pub fn add_to_mempool(&mut self, tx: Transaction) ->Result<(),MempoolError> {
        tx.verify_transaction().map_err(|_|MempoolError::InvalidSignature)?;

        let expected_nonce = self.nonces.get(&tx.from).unwrap_or(&0)
            + self.mempool.iter().filter(|t| t.from == tx.from).count() as u64;

        if expected_nonce != tx.nonce {
            return Err(
                MempoolError::InvalidNonce
            );
        }

        let pending_balance: u64 = self
            .mempool
            .iter()
            .filter(|transaction| transaction.from == tx.from)
            .map(|tt| tt.amount + tt.fee)
            .sum();

        match self.accounts.get(&tx.from) {
            Some(balance) => {
                if balance.coins >= tx.amount + tx.fee + pending_balance {
                    self.mempool.push(tx);
                    Ok(())
                } else {
                    println!("false: not enough money");
                    Err(MempoolError::InsufficientFunds)
                }
            }
            None => {
                println!("false: no account");
                 Err(MempoolError::AccountNotFound)
            }
        }
    }

    pub fn check_balance(&self, public_key: &PublicKey, amount: u64) -> bool {
        if let Some(balance) = self.accounts.get(public_key) {
            return amount <= balance.coins;
        }
        false
    }

    fn execute_program(
        &mut self,
        program_id: &PublicKey,
        instruction_data: &[u8],
        caller: &PublicKey,
        _amount: u64,
    ) {
        if program_id == &self.faucet_program_id {
            // Команда "1" означает "Начислить 100 монет"
            if instruction_data == [1] {
                if let Some(user) = self.accounts.get_mut(caller) {
                    user.coins += 100;
                }
            } else {
                println!("Error executing program")
            }
        }

        if program_id == &self.notebook_program_id
            && !instruction_data.is_empty()
            && instruction_data[0] == 2
        {
            if instruction_data.len() < 34 {
                println!("Error: Too short instruction data");
                return;
            }

            let target_key_bytes = &instruction_data[1..34];
            let text_bytes = &instruction_data[34..];

            if let Ok(target_key) = PublicKey::from_slice(target_key_bytes) {
                if let Some(acc) = self.accounts.get_mut(&target_key) {
                    if acc.owner == *program_id {

                        if target_key == *caller {
                            println!("✅ Owner check AND Signer check passed. Writing data...");
                            acc.data = text_bytes.to_vec();
                        } else {
                            println!("🛡️ SECURITY ERROR 2: Caller does not own this data account! Access denied.");
                        }
                        
                        println!("Owner check passed. Writing data...");
                        // acc.data = text_bytes.to_vec();
                    } else {
                        println!(
                            "SECURITY ERROR: Program does not own this account! Access denied."
                        );
                    }
                } else {
                    println!("Error: Target account not found");
                }
            }
        }
    }

    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), TransferError> {
        let sender_balance = self
            .accounts
            .get_mut(&tx.from)
            .ok_or(TransferError::SenderNotFound)?;

        if sender_balance.coins < tx.amount + tx.fee {
            return Err(TransferError::InsufficientFunds);
        }

        sender_balance.coins -= tx.amount + tx.fee;

        let is_program = self
            .accounts
            .get(&tx.to)
            .map(|a| a.executable)
            .unwrap_or(false);

        if is_program {
            self.execute_program(&tx.to, &tx.instruction_data, &tx.from, tx.amount);
            return Ok(());
        }

        let receiver_balance = self.accounts.entry(tx.to).or_insert(Account {
            coins: 0,
            data: vec![],
            owner: tx.to,
            executable: false,
        });

        receiver_balance.coins += tx.amount;
        *self.nonces.entry(tx.from).or_insert(0) += 1;

        Ok(())
    }

    pub fn add_block(&mut self, miner: PublicKey) -> bool {
        let mut transactions = std::mem::take(&mut self.mempool);
        transactions.sort_by(|tx1, tx2| tx2.fee.cmp(&tx1.fee));

        let previous_hash = match self.vec.last() {
            Some(block) => block.hash.clone(),
            None => "0".to_string(),
        };
        let timestamp = current_time();
        let index = self.vec.len() as u32;

        let mut total_fees = 0;
        for tx in &transactions {
            match self.apply_transaction(tx) {
                Ok(_) => {
                    total_fees += tx.fee;
                    println!("transaction successfully added")
                }
                Err(err) => {
                    eprintln!("Error handling transaction {}: {:?}", tx.from, err);
                    return false;
                }
            }
        }

        let coinbase_amount = BLOCK_REWARD + total_fees;
        let coinbase_tx = CoinbaseTransaction {
            to: miner,
            amount: coinbase_amount,
        };

        let first_block: Block = Block::new(
            index,
            timestamp,
            transactions,
            previous_hash,
            self.difficulty,
            coinbase_tx,
        );

        let miner_balance = self.accounts.entry(miner).or_insert(Account {
            coins: 0,
            data: vec![],
            owner: miner,
            executable: false,
        });
        miner_balance.coins += coinbase_amount;

        self.vec.push(first_block);

        true
    }

    pub fn is_valid(&self) -> Result<bool, serde_json::Error> {
        if self.vec.is_empty() {
            return Ok(false);
        }

        let genesis = &self.vec[0];
        if genesis.index != 0 || genesis.previous_hash != "0" {
            return Ok(false);
        }

        let transactions_str = serde_json::to_string(&genesis.transactions)?;
        let coinbase_str = serde_json::to_string(&genesis.coinbase)?;
        let base = format!(
            "{}{}{}{}{}",
            genesis.index, genesis.timestamp, genesis.previous_hash, transactions_str, coinbase_str,
        );

        let right_hash = format!("{}{}", base, genesis.nonce);

        if make_hash(&right_hash) != genesis.hash {
            return Ok(false);
        }

        if !genesis
            .hash
            .starts_with(&"0".repeat(self.difficulty as usize))
        {
            return Ok(false);
        }

        let total_fee: u64 = genesis.transactions.iter().map(|t| t.fee).sum();
        let expected_coinbase = BLOCK_REWARD + total_fee;

        if genesis.coinbase.amount != expected_coinbase {
            return Ok(false);
        }

        for j in 1..self.vec.len() {
            if self.vec[j].previous_hash != self.vec[j - 1].hash {
                return Ok(false);
            }
            let transactions_str = serde_json::to_string(&self.vec[j].transactions)?;
            let coinbase_str = serde_json::to_string(&self.vec[j].coinbase)?;
            let base = format!(
                "{}{}{}{}{}",
                self.vec[j].index,
                self.vec[j].timestamp,
                self.vec[j].previous_hash,
                transactions_str,
                coinbase_str,
            );
            let right_hash = format!("{}{}", base, self.vec[j].nonce);

            if make_hash(&right_hash) != self.vec[j].hash {
                return Ok(false);
            }

            if !self.vec[j]
                .hash
                .starts_with(&"0".repeat(self.difficulty as usize))
            {
                return Ok(false);
            }

            let total_fee: u64 = self.vec[j].transactions.iter().map(|t| t.fee).sum();
            let expected_coinbase = BLOCK_REWARD + total_fee;

            if self.vec[j].coinbase.amount != expected_coinbase {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Block {
    pub fn new(
        index: u32,
        timestamp: u64,
        transactions: Vec<Transaction>,
        previous_hash: String,
        difficulty: u32,
        coinbase: CoinbaseTransaction,
    ) -> Self {
        let (nonce, hash) = mine(
            difficulty as usize,
            index,
            timestamp,
            &transactions,
            &previous_hash,
            &coinbase,
        );

        Block {
            index,
            timestamp,
            transactions,
            hash,
            previous_hash,
            nonce,
            coinbase,
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
                        match peer_chain.is_valid() {
                            Ok(true) => {
                                println!("Peer chain is longer! Replacing ours.");
                                *lock = peer_chain;
                            }
                            Ok(false) => {
                                println!("Received invalid blockchain.");
                            }
                            Err(e) => {
                                eprintln!("Validation error: {}", e);
                            }
                        }
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
  async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_, faucet_program_id) = generate_keypair();
    let (_, notebook_program_id) = generate_keypair();
    let (secret_key_from, public_key_from) = generate_keypair();
    let (_, public_key_to) = generate_keypair();
    let mut tx = sign_transaction(public_key_to, 100, vec![], &secret_key_from, 0, 0).unwrap();

    println!("valid = {:?}", tx.verify_transaction());
    tx.amount = 101;
    println!("after tamper = {:?}", tx.verify_transaction());

    let args: Vec<String> = std::env::args().collect();

    let server_port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(8080);
    let peer_port: Option<u16> = args.get(2).and_then(|s| s.parse().ok());

    println!("Starting node on port {}...", server_port);

    let chain = Arc::new(Mutex::new(Blockchain::new(
        public_key_from,
        faucet_program_id,
        notebook_program_id,
    )));

    if server_port == 8080 {
        let tx1 = sign_transaction(public_key_to, 101, vec![], &secret_key_from, 0, 0).unwrap();
        println!("valid = {:?}", tx1.verify_transaction());
        let tx2 = sign_transaction(public_key_to, 102, vec![], &secret_key_from, 0, 1).unwrap();
        println!("valid = {:?}", tx2.verify_transaction());
        let tx3 = sign_transaction(public_key_to, 103, vec![], &secret_key_from, 0, 2).unwrap();
        println!("valid = {:?}", tx3.verify_transaction());
        let mut lock = chain.lock().await;
        let _ = lock.add_to_mempool(tx1);
        let _ = lock.add_to_mempool(tx2);
        let _ = lock.add_to_mempool(tx3);
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

    tokio::signal::ctrl_c().await?;

    Ok(())
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
    coinbase: &CoinbaseTransaction,
) -> (u64, String) {
    let transactions_str =
        serde_json::to_string(transactions).expect("serialization should not fail");
    let coinbase_str = serde_json::to_string(coinbase).expect("serialization should not fail");
    let base = format!(
        "{}{}{}{}{}",
        index, timestamp, previous_hash, transactions_str, coinbase_str
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
        let (_, notebook_program_id) = generate_keypair();
        let (_, faucet_program_id) = generate_keypair();
        let (_, miner_pubkey) = generate_keypair();
        let difficulty = [1, 3, 4];
        for &diff in &difficulty {
            // 1. Фиксируем время ДО выполнения функции
            let start = Instant::now();

            let mut bc = Blockchain {
                accounts: HashMap::new(),
                difficulty: diff,
                vec: vec![],
                mempool: vec![],
                faucet_program_id,
                notebook_program_id,
                nonces: HashMap::new(),
            };

            let genesis_coinbase = CoinbaseTransaction {
                to: miner_pubkey,
                amount: BLOCK_REWARD,
            };

            bc.vec.push(Block::new(
                0,
                current_time(),
                vec![],
                "0".into(),
                diff,
                genesis_coinbase,
            ));
            let (secret_key_from, _) = generate_keypair();
            let (_, public_key_to) = generate_keypair();
            let tx = sign_transaction(public_key_to, 200, vec![], &secret_key_from, 0, 0).unwrap();
            println!("valid = {:?}", tx.verify_transaction());
            let _ = bc.add_to_mempool(tx);

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

        let mut transaction = sign_transaction(to_public_key, 100, vec![], &from_secret_key, 0, 0).unwrap();

        let is_valid = transaction.verify_transaction().is_ok();
        assert!(is_valid);

        transaction.amount = 101;

        assert!(transaction.verify_transaction().is_err());
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
        let (_, notebook_program_id) = generate_keypair();
        let (_, faucet_program_id) = generate_keypair();
        let (secret_key_from, public_key_from) = generate_keypair();
        let (_, public_key_to) = generate_keypair();
        let (_, miner_pubkey) = generate_keypair();

        let tx1 = sign_transaction(public_key_to, 101, vec![], &secret_key_from, 0, 0).unwrap();
        println!("valid 1 = {:?}", tx1.verify_transaction());
        let tx2 = sign_transaction(public_key_to, 102, vec![], &secret_key_from, 0, 1).unwrap();
        println!("valid 2 = {:?}", tx2.verify_transaction());
        let mut tx3 = sign_transaction(public_key_to, 103, vec![], &secret_key_from, 0, 2).unwrap();
        tx3.amount = 999;
        println!("valid 3 = {:?}", tx3.verify_transaction());

        let diff = 4;

        let mut accounts = HashMap::new();
        accounts.insert(
            public_key_from,
            Account {
                coins: 203,
                data: vec![],
                owner: public_key_from,
                executable: false,
            },
        );
        accounts.insert(
            public_key_to,
            Account {
                coins: 0,
                data: vec![],
                owner: public_key_to,
                executable: false,
            },
        );

        let mut bc = Blockchain {
            accounts,
            difficulty: diff,
            vec: vec![],
            mempool: vec![],
            faucet_program_id,
            notebook_program_id,
            nonces: HashMap::new(),
        };

        let genesis_coinbase = CoinbaseTransaction {
            to: miner_pubkey,
            amount: BLOCK_REWARD,
        };

        bc.vec.push(Block::new(
            0,
            current_time(),
            vec![],
            "0".into(),
            diff,
            genesis_coinbase,
        ));

        let _ = bc.add_to_mempool(tx1);
        let _ = bc.add_to_mempool(tx2);
        let _ = bc.add_to_mempool(tx3);

        bc.add_block(miner_pubkey);
        let last_block = bc.vec.last().unwrap();

        assert_eq!(last_block.transactions.len(), 2);
    }

    #[test]
    fn test_check_balance() {
        let (_, notebook_program_id) = generate_keypair();
        let (_, faucet_program_id) = generate_keypair();
        let (secret_key_from, public_key_from) = generate_keypair();
        let (_, public_key_to) = generate_keypair();
        let (_, miner_pubkey) = generate_keypair();

        let tx1 = sign_transaction(public_key_to, 50, vec![], &secret_key_from, 0, 0).unwrap();
        println!("valid 1 = {:?}", tx1.verify_transaction());
        let tx2 = sign_transaction(public_key_to, 200, vec![], &secret_key_from, 0, 1).unwrap();
        println!("valid 2 = {:?}", tx2.verify_transaction());

        let diff = 4;

        let mut accounts = HashMap::new();
        accounts.insert(
            public_key_from,
            Account {
                coins: 100,
                data: vec![],
                owner: public_key_from,
                executable: false,
            },
        );
        accounts.insert(
            public_key_to,
            Account {
                coins: 0,
                data: vec![],
                owner: public_key_to,
                executable: false,
            },
        );

        let mut bc = Blockchain {
            accounts,
            difficulty: diff,
            vec: vec![],
            mempool: vec![],
            faucet_program_id,
            notebook_program_id,
            nonces: HashMap::new(),
        };

        let genesis_coinbase = CoinbaseTransaction {
            to: miner_pubkey,
            amount: BLOCK_REWARD,
        };

        bc.vec.push(Block::new(
            0,
            current_time(),
            vec![],
            "0".into(),
            diff,
            genesis_coinbase,
        ));

        assert!(bc.add_to_mempool(tx1).is_ok());

        assert!(bc.add_to_mempool(tx2).is_err());

        assert_eq!(bc.mempool.len(), 1);

        assert!(bc.add_block(miner_pubkey));
        let last_block = bc.vec.last().unwrap();

        assert_eq!(last_block.transactions.len(), 1);

        println!("{:?}", bc.accounts);

        // Баланс отправителя уменьшился на 50
        assert_eq!(bc.accounts.get(&public_key_from).unwrap().coins, 50);

        assert_eq!(bc.accounts.get(&public_key_to).unwrap().coins, 50);
    }

    #[test]
    fn test_execue_programm() {
        let (_, notebook_program_id) = generate_keypair();
        let (_, faucet_program_id) = generate_keypair();
        let (secret_key_from, public_key_from) = generate_keypair();
        let (_, miner_pubkey) = generate_keypair(); // ← ДОБАВЬ МАЙНЕРА

        let diff = 4;

        let mut accounts = HashMap::new();
        accounts.insert(
            public_key_from,
            Account {
                coins: 0,
                data: vec![],
                owner: public_key_from,
                executable: false,
            },
        );

        let mut bc = Blockchain {
            accounts,
            difficulty: diff,
            vec: vec![],
            mempool: vec![],
            faucet_program_id,
            notebook_program_id,
            nonces: HashMap::new(),
        };

        bc.deploy_program(faucet_program_id, vec![]);

        let tx1 = sign_transaction(faucet_program_id, 0, vec![1], &secret_key_from, 0, 0).unwrap();
        println!("valid 1 = {:?}", tx1.verify_transaction());
        assert!(bc.add_to_mempool(tx1).is_ok());
        assert!(bc.add_block(miner_pubkey));
        let last_block = bc.vec.last().unwrap();

        assert_eq!(last_block.transactions.len(), 1);

        println!("{:?}", bc.accounts);

        // Баланс отправителя уменьшился на 50
        assert_eq!(bc.accounts.get(&public_key_from).unwrap().coins, 100);
    }

    #[test]
    fn test_notebook_security() {
        let (_, notebook_program_id) = generate_keypair();
        let (_, faucet_program_id) = generate_keypair();
        let (secret_key_from, public_key_from) = generate_keypair();
   
        let (_, miner_pubkey) = generate_keypair();
        let diff = 4;

        let mut accounts = HashMap::new();
        accounts.insert(
            public_key_from,
            Account {
                coins: 0,
                data: vec![],
                owner: public_key_from,
                executable: false,
            },
        );

        let mut bc = Blockchain {
            accounts,
            difficulty: diff,
            vec: vec![],
            mempool: vec![],
            faucet_program_id,
            notebook_program_id,
            nonces: HashMap::new(),
        };

        bc.deploy_program(notebook_program_id, vec![]);
        // bc.create_data_account(data_account_key, notebook_program_id);
        bc.create_data_account(public_key_from, notebook_program_id);
        let mut data = vec![2]; // Команда 2
        // data.extend_from_slice(&data_account_key.serialize()); // 33 байта адреса
        data.extend_from_slice(&public_key_from.serialize());
        data.extend_from_slice(b"Hello Solana!"); // Текст

        let tx1 = sign_transaction(notebook_program_id, 0, data, &secret_key_from, 0, 0).unwrap();
        println!("valid 1 = {:?}", tx1.verify_transaction());
        assert!(bc.add_to_mempool(tx1).is_ok());
        assert!(bc.add_block(miner_pubkey));
        let last_block = bc.vec.last().unwrap();

        assert_eq!(last_block.transactions.len(), 1);

        println!("{:?}", bc.accounts);

        assert_eq!(
            bc.accounts.get(&public_key_from).unwrap().data,
            b"Hello Solana!"
        );
    }

    #[test]
    fn test_notebook_hack_attempt() {
        let (_, notebook_program_id) = generate_keypair();
        let (_, faucet_program_id) = generate_keypair();
        let (secret_key_from, public_key_from) = generate_keypair();
        let (_, victim_key) = generate_keypair();
        let (_, miner_pubkey) = generate_keypair();

        let diff = 4;

        let mut accounts = HashMap::new();
        accounts.insert(
            public_key_from,
            Account {
                coins: 0,
                data: vec![],
                owner: public_key_from,
                executable: false,
            },
        );
        accounts.insert(
            victim_key,
            Account {
                coins: 0,
                data: vec![],
                owner: victim_key,
                executable: false,
            },
        );

        let mut bc = Blockchain {
            accounts,
            difficulty: diff,
            vec: vec![],
            mempool: vec![],
            faucet_program_id,
            notebook_program_id,
            nonces: HashMap::new(),
        };

        bc.deploy_program(notebook_program_id, vec![]);
        bc.create_data_account(victim_key, notebook_program_id);

        let mut data = vec![2]; // Команда 2
        data.extend_from_slice(&victim_key.serialize()); // 33 байта адреса
        data.extend_from_slice(b"Hello Solana!"); // Текст

        let tx1 = sign_transaction(notebook_program_id, 0, data, &secret_key_from, 0, 0).unwrap();
        println!("valid 1 = {:?}", tx1.verify_transaction());
        assert!(bc.add_to_mempool(tx1).is_ok());
        assert!(bc.add_block(miner_pubkey));
        let last_block = bc.vec.last().unwrap();

        assert_eq!(last_block.transactions.len(), 1);

        println!("{:?}", bc.accounts);

        assert_eq!(bc.accounts.get(&victim_key).unwrap().data, Vec::<u8>::new(),);
    }

    #[test]
    fn test_genesis_nonce_initialized() {
        let (_, faucet_program_id) = generate_keypair();
        let (_, notebook_program_id) = generate_keypair();
        let (_, genesis_pubkey) = generate_keypair();

        let bc = Blockchain::new(genesis_pubkey, faucet_program_id, notebook_program_id);

        // Genesis аккаунт должен иметь nonce = 0 после создания блокчейна
        let genesis_nonce = bc.nonces.get(&genesis_pubkey);
        assert!(
            genesis_nonce.is_some(),
            "Genesis nonce должен быть инициализирован"
        );
        assert_eq!(
            *genesis_nonce.unwrap(),
            0,
            "Genesis nonce должен быть равен 0"
        );
    }

    #[test]
    fn test_fee_priority() {
        // Создать 3 tx с разными fee: 10, 50, 30
        // Добавить все в mempool
        // Вызвать add_block(miner)
        // Проверить что в блоке tx идут в порядке: fee=50, fee=30, fee=10

        let (_, notebook_program_id) = generate_keypair();
        let (_, faucet_program_id) = generate_keypair();
        let (secret_key_from, public_key_from) = generate_keypair();
        let (_, public_key_to) = generate_keypair();
        let (_, miner_pubkey) = generate_keypair();

        let tx1 = sign_transaction(public_key_to, 25, vec![], &secret_key_from, 30, 0).unwrap();
        println!("valid 1 = {:?}", tx1.verify_transaction());
        let tx2 = sign_transaction(public_key_to, 20, vec![], &secret_key_from, 10, 1).unwrap();
        println!("valid 2 = {:?}", tx2.verify_transaction());
        let tx3 = sign_transaction(public_key_to, 15, vec![], &secret_key_from, 50, 2).unwrap();
        println!("valid 3 = {:?}", tx3.verify_transaction());

        let diff = 4;

        let mut accounts = HashMap::new();
        accounts.insert(
            public_key_from,
            Account {
                coins: 203,
                data: vec![],
                owner: public_key_from,
                executable: false,
            },
        );
        accounts.insert(
            public_key_to,
            Account {
                coins: 0,
                data: vec![],
                owner: public_key_to,
                executable: false,
            },
        );

        let mut bc = Blockchain {
            accounts,
            difficulty: diff,
            vec: vec![],
            mempool: vec![],
            faucet_program_id,
            notebook_program_id,
            nonces: HashMap::new(),
        };

        let genesis_coinbase = CoinbaseTransaction {
            to: miner_pubkey,
            amount: BLOCK_REWARD,
        };

        bc.vec.push(Block::new(
            0,
            current_time(),
            vec![],
            "0".into(),
            diff,
            genesis_coinbase,
        ));

        let _ = bc.add_to_mempool(tx1);
        let _ = bc.add_to_mempool(tx2);
        let _ = bc.add_to_mempool(tx3);

        bc.add_block(miner_pubkey);
        let last_block = bc.vec.last().unwrap();
        println!("{:?}", last_block.transactions);
        assert_eq!(last_block.transactions[0].fee, 50);
        assert_eq!(last_block.transactions[1].fee, 30);
        assert_eq!(last_block.transactions[2].fee, 10);
    }

    #[test]
    fn test_miner_reward() {
        // Создать genesis с balance=1000
        // Создать 2 tx с fee=10 и fee=20
        // Вызвать add_block(miner)
        // Проверить что баланс майнера = BLOCK_REWARD + 30

        let (_, notebook_program_id) = generate_keypair();
        let (_, faucet_program_id) = generate_keypair();
        let (secret_key_from, public_key_from) = generate_keypair();
        let (_, public_key_to) = generate_keypair();
        let (_, miner_pubkey) = generate_keypair();

        let tx1 = sign_transaction(public_key_to, 25, vec![], &secret_key_from, 20, 0).unwrap();
        println!("valid 1 = {:?}", tx1.verify_transaction());
        let tx2 = sign_transaction(public_key_to, 20, vec![], &secret_key_from, 10, 1).unwrap();
        println!("valid 2 = {:?}", tx2.verify_transaction());

        let diff = 4;

        let mut accounts = HashMap::new();
        accounts.insert(
            public_key_from,
            Account {
                coins: 1000,
                data: vec![],
                owner: public_key_from,
                executable: false,
            },
        );
        accounts.insert(
            public_key_to,
            Account {
                coins: 0,
                data: vec![],
                owner: public_key_to,
                executable: false,
            },
        );

        let mut nonces = HashMap::new();
        nonces.insert(public_key_from, 0);
        let mut bc = Blockchain {
            accounts,
            difficulty: diff,
            vec: vec![],
            mempool: vec![],
            faucet_program_id,
            notebook_program_id,
            nonces,
        };

        let genesis_coinbase = CoinbaseTransaction {
            to: miner_pubkey,
            amount: BLOCK_REWARD,
        };

        bc.vec.push(Block::new(
            0,
            current_time(),
            vec![],
            "0".into(),
            diff,
            genesis_coinbase,
        ));

        let _ = bc.add_to_mempool(tx1);
        let _ = bc.add_to_mempool(tx2);

        bc.add_block(miner_pubkey);

        let last_block = bc.vec.last().unwrap();

        assert_eq!(last_block.transactions[0].fee, 20);
        assert_eq!(last_block.transactions[1].fee, 10);
        assert_eq!(
            bc.accounts.get(&miner_pubkey).unwrap().coins,
            BLOCK_REWARD + 30
        );
    }
}
