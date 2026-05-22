use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Block {
    pub index: u32,
    pub timestamp: u64,
    pub data: String,
    pub previous_hash: String,
    pub hash: String,
}


impl Block {
    pub fn new(index: u32, data: String, previous_hash: String) ->Self {
    let start = SystemTime::now();
    let timestamp = start
        .duration_since(UNIX_EPOCH)
        .expect("Время до эпохи Unix!")
        .as_secs();
    let result = format!("{}{}{}{}", index,timestamp, data, previous_hash);
    
        Block{
            index,
            timestamp,
            data,
            previous_hash,
            hash: hash(&result),
        }
    }
}

//hash(result)
fn hash(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

fn main() {

    let bl1 = Block::new(0, String::from("test123"), String::from("0"));

    println!("block1 {}",bl1.hash);
    println!("block1 {}",bl1.previous_hash);

     let bl2 = Block::new(1, String::from("test345"), bl1.hash);

    println!("block2 {}",bl2.hash);
    println!("block2 {}",bl2.previous_hash);

}
