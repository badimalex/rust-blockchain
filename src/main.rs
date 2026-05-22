use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Block {
    pub index: u32,
    pub timestamp: u64,
    pub data: String,
    pub previous_hash: String,
    pub hash: String,
}

pub struct Blockchain {
    pub vec: Vec<Block>,
}

impl Blockchain {
    pub fn new() -> Self {
        let data = "0".to_string();
        let timestamp = current_time();
        let previous_hash = "0".to_string();
        let result = format!("{}{}{}{}", 0, timestamp, data, previous_hash);

        Blockchain {
            vec: vec![Block {
                index: 0,
                timestamp,
                data,
                previous_hash,
                hash: hash(&result),
            }],
        }
    }

    pub fn add_block(&mut self, data: String) {
        let last = match self.vec.last() {
            Some(block) => block.hash.clone(),
            None => "0".to_string(),
        };
        let index = self.vec.len() as u32;

        let bl1: Block = Block::new(index, data, last);
        self.vec.push(bl1);
    }

    pub fn is_valid(&self) -> bool {
        for j in 1..self.vec.len() {
            if self.vec[j].previous_hash != self.vec[j - 1].hash {
                return false;
            }
            let right_hash = format!(
                "{}{}{}{}",
                 self.vec[j].index, self.vec[j].timestamp, self.vec[j].data, self.vec[j].previous_hash
            );

            if hash(&right_hash) != self.vec[j].hash {
                return false;
            }
        }
        true
    }
}

impl Block {
    pub fn new(index: u32, data: String, previous_hash: String) -> Self {
        let timestamp = current_time();
        let result = format!("{}{}{}{}", index, timestamp, data, previous_hash);

        Block {
            index,
            timestamp,
            data,
            previous_hash,
            hash: hash(&result),
        }
    }
}

fn current_time() -> u64 {
    let start = SystemTime::now();
    let timestamp = start
        .duration_since(UNIX_EPOCH)
        .expect("Время до эпохи Unix!")
        .as_secs();

    return timestamp;
}

fn hash(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

fn main() {
    let mut chain = Blockchain::new();

    chain.add_block(String::from("send 1 usd"));
    chain.add_block(String::from("send 2 usd"));
    chain.add_block(String::from("send 3 usd"));

    println!("{}", chain.is_valid())
}
