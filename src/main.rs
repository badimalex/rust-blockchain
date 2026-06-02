use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

#[derive(Serialize, Deserialize, Debug)]
pub struct Block {
    pub index: u32,
    pub timestamp: u64,
    pub data: String,
    pub previous_hash: String,
    pub hash: String,
    pub nonce: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Blockchain {
    pub vec: Vec<Block>,
    pub difficulty: u32,
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
            vec: vec![Block::new(0, timestamp, "0".into(), "0".into(), difficulty)],
        }
    }

    pub fn add_block(&mut self, data: String) {
        let previous_hash = match self.vec.last() {
            Some(block) => block.hash.clone(),
            None => "0".to_string(),
        };
        let timestamp = current_time();
        let index = self.vec.len() as u32;

        let first_block: Block = Block::new(index, timestamp, data, previous_hash, self.difficulty);
        self.vec.push(first_block);
    }

    pub fn is_valid(&self) -> bool {
        for j in 1..self.vec.len() {
            if self.vec[j].previous_hash != self.vec[j - 1].hash {
                return false;
            }
            let right_hash = format!(
                "{}{}{}{}{}",
                self.vec[j].index,
                self.vec[j].timestamp,
                self.vec[j].data,
                self.vec[j].previous_hash,
                self.vec[j].nonce
            );
            if !self.vec[j]
                .hash
                .starts_with(&"0".repeat(self.difficulty as usize))
            {
                return false;
            }

            if make_hash(&right_hash) != self.vec[j].hash {
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
        data: String,
        previous_hash: String,
        difficulty: u32,
    ) -> Self {
        let (nonce, hash) = mine(difficulty as usize, index, timestamp, &data, &previous_hash);

        Block {
            index,
            timestamp,
            data,
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
        .expect("Время до эпохи Unix!")
        .as_secs()
}

fn make_hash(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

async fn start_server(port: u16, chain: Arc<Mutex<Blockchain>>) -> std::io::Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

    loop {
        let (socket, addr) = listener.accept().await?;

        let mock_chain = Arc::clone(&chain);

        tokio::spawn(async move {
            if let Err(err) = handle_client(socket, mock_chain).await {
                eprintln!("Ошибка при обработке клиента {}: {}", addr, err);
            }
        });
    }
}

async fn sync_with_peer(addr: &str, clone_chain: Arc<Mutex<Blockchain>>) {
    match TcpStream::connect(addr).await {
        Ok(mut stream) => {
            let mut buffer = String::new();

            if stream.read_to_string(&mut buffer).await.is_ok() {
                if let Ok(peer_chain) = serde_json::from_str::<Blockchain>(&buffer) {
                    println!("Получена цепочка от пира. Длина: {}", peer_chain.vec.len());

                    // Блокируем наш мьютекс на минимально возможное время
                    let mut local_chain = clone_chain.lock().await;
                    if peer_chain.vec.len() > local_chain.vec.len() {
                        println!("Цепочка пира длиннее! Заменяем нашу.");
                        *local_chain = peer_chain;
                    } else {
                        println!("Наша цепочка длиннее или равна. Ничего не меняем.");
                    }
                } else {
                    eprintln!("Ошибка парсинга JSON. Полученные данные: {}", buffer);
                }
            } else {
                eprintln!("Ошибка чтения из потока");
            }
        }
        Err(e) => {
            eprintln!("Ошибка подключения к пиру {}: {}", addr, e);
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let server_port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(8080);
    let peer_port: Option<u16> = args.get(2).and_then(|s| s.parse().ok());

    let chain = Arc::new(Mutex::new(Blockchain::new()));

    if server_port == 8080 {
        let mut lock = chain.lock().await;
        lock.add_block(String::from("send 1 usd"));
        lock.add_block(String::from("send 2 usd"));
        lock.add_block(String::from("send 3 usd"));
    }

    let clone: Arc<Mutex<Blockchain>> = chain.clone();
    tokio::spawn(async move {
        if let Err(err) = start_server(server_port, clone).await {
            eprintln!("Ошибка сервера на порту {}: {}", server_port, err);
        }
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    if let Some(p_port) = peer_port {
        let peer_addr = format!("127.0.0.1:{}", p_port);
        sync_with_peer(&peer_addr, chain.clone()).await;
    }

    let difficulty = [1, 3, 4];
    for &diff in &difficulty {
        // 1. Фиксируем время ДО выполнения функции
        let start = Instant::now();

        let mut bc = Blockchain {
            difficulty: diff,
            vec: vec![],
        };
        bc.vec.push(Block::new(
            0,
            current_time(),
            "genesis".into(),
            "0".into(),
            diff,
        ));
        bc.add_block("Hello blockchain".to_string());

        // 3. Вычисляем прошедшее время
        let elapsed = start.elapsed();

        println!("Функция {} сгенерировала за {:?}", diff, elapsed);
    }

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
    data: &str,
    previous_hash: &str,
) -> (u64, String) {
    let base = format!("{}{}{}{}", index, timestamp, data, previous_hash);
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
    use std::time::Instant;

    use super::*;

    #[test]
    fn test_mining_hello_blockchain() {
        let difficulty = [2, 3, 4, 5];
        for &diff in &difficulty {
            let prefix = "Hello blockchain";

            // 1. Фиксируем время ДО выполнения функции
            let start = Instant::now();

            // Вызываем вашу готовую функцию
            let (nonce, hash) = mine(diff, 0, current_time(), prefix, "0");

            // 3. Вычисляем прошедшее время
            let elapsed = start.elapsed();

            println!("Функция сгенерировала {} за {:?}", nonce, elapsed);
            println!("Подошедший nonce: {}", nonce);
            println!("Полученный хеш: {}", hash);

            let expected_prefix = "0".repeat(diff);
            assert!(
                hash.starts_with(&expected_prefix),
                "Хеш должен начинаться с '{}' при сложности {}",
                expected_prefix,
                diff
            );
        }
    }
}
