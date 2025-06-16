use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::convert::TryInto;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Serialize, Deserialize)]
struct Keypair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl Keypair {
    fn generate() -> Self {
        let mut csprng = OsRng;
        let secret_scalar = Scalar::random(&mut csprng);
        let public_point = secret_scalar * RISTRETTO_BASEPOINT_POINT;
        Keypair {
            secret: secret_scalar.to_bytes(),
            public: public_point.compress().to_bytes(),
        }
    }

    fn save_to_file(&self, path: &str) {
        let json = serde_json::to_string(self).unwrap();
        fs::write(path, json).unwrap();
    }

    fn load_from_file(path: &str) -> Option<Self> {
        let json = fs::read_to_string(path).ok()?;
        serde_json::from_str(&json).ok()
    }

    fn secret_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.secret)
    }

    fn public_point(&self) -> RistrettoPoint {
        CompressedRistretto(self.public).decompress().unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Signature {
    R: [u8; 32],
    s: [u8; 32],
}

impl Signature {
    fn sign(msg: &[u8], key: &Keypair) -> Self {
        let mut csprng = OsRng;
        let k = Scalar::random(&mut csprng);
        let R = (k * RISTRETTO_BASEPOINT_POINT).compress();

        let mut hasher = Sha512::new();
        hasher.update(R.as_bytes());
        hasher.update(&key.public);
        hasher.update(msg);

        let hash_bytes = Sha512::digest(data_to_hash);
        let h = Scalar::from_bytes_mod_order_wide(hash_bytes.as_slice().try_into().unwrap());

        let s = k + h * key.secret_scalar();

        Signature {
            R: R.to_bytes(),
            s: s.to_bytes(),
        }
    }

    fn verify(&self, msg: &[u8], pubkey: &RistrettoPoint) -> bool {
        let R = match CompressedRistretto(self.R).decompress() {
            Some(r) => r,
            None => return false,
        };
        let s_ct = Scalar::from_canonical_bytes(self.s);
        if s_ct.is_none().into() {
            return false;
        }
        let s = s_ct.unwrap();

        let mut hasher = Sha512::new();
        hasher.update(&self.R);
        hasher.update(pubkey.compress().as_bytes());
        hasher.update(msg);
        let hash_bytes = Sha512::digest(data_to_hash);
        let h = Scalar::from_bytes_mod_order_wide(hash_bytes.as_slice().try_into().unwrap());

        s * RISTRETTO_BASEPOINT_POINT == R + h * pubkey
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Transaction {
    from: String,
    to: String,
    amount: u64,
    signature: Option<Signature>,
}

impl Transaction {
    fn sign(&mut self, key: &Keypair) {
        let msg = self.serialize_core();
        self.signature = Some(Signature::sign(&msg, key));
    }

    fn verify(&self) -> bool {
        if self.from == "SYSTEM" {
            return true;
        }
        let sig = match &self.signature {
            Some(s) => s,
            None => return false,
        };
        let _pubkey_bytes = match hex::decode(&self.from) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let pubkey_bytes = hex::decode(&self.from).expect("Invalid hex in sender address");
        let compressed =
            CompressedRistretto::from_slice(&pubkey_bytes).expect("Invalid public key bytes");
        let pubkey = match compressed.decompress() {
            Some(p) => p,
            None => return false,
        };
        sig.verify(&self.serialize_core(), &pubkey)
    }

    fn serialize_core(&self) -> Vec<u8> {
        serde_json::to_vec(&(self.from.clone(), self.to.clone(), self.amount)).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Block {
    index: u64,
    timestamp: u128,
    transactions: Vec<Transaction>,
    prev_hash: String,
    nonce: u64,
    hash: String,
}

impl Block {
    fn new(index: u64, transactions: Vec<Transaction>, prev_hash: String) -> Self {
        let timestamp = now();
        let mut nonce = 0;
        loop {
            let block = Block {
                index,
                timestamp,
                transactions: transactions.clone(),
                prev_hash: prev_hash.clone(),
                nonce,
                hash: String::new(),
            };
            let h = block.compute_hash();
            if h.starts_with("0000") {
                hash = h;
                break;
            }
            nonce += 1;
        }
        Block {
            index,
            timestamp,
            transactions,
            prev_hash,
            nonce,
            hash,
        }
    }

    fn compute_hash(&self) -> String {
        let block_data = serde_json::to_string(&(
            self.index,
            self.timestamp,
            &self.transactions,
            &self.prev_hash,
            self.nonce,
        ))
        .unwrap();
        let hash = Sha512::digest(block_data.as_bytes());
        hex::encode(&hash[..])
    }
}

#[derive(Debug)]
struct Blockchain {
    chain: Vec<Block>,
    pending: Vec<Transaction>,
    difficulty: usize,
}

impl Blockchain {
    fn new() -> Self {
        let mut bc = Blockchain {
            chain: vec![],
            pending: vec![],
            difficulty: 4,
        };
        bc.create_genesis_block();
        bc
    }

    fn create_genesis_block(&mut self) {
        let genesis = Block::new(0, vec![], String::from("0"));
        self.chain.push(genesis);
    }

    fn add_transaction(&mut self, tx: Transaction) -> bool {
        if tx.verify() {
            self.pending.push(tx);
            true
        } else {
            false
        }
    }

    fn mine_block(&mut self, miner_address: String) {
        let reward_tx = Transaction {
            from: "SYSTEM".into(),
            to: miner_address,
            amount: 50,
            signature: None,
        };
        let mut transactions = self.pending.clone();
        transactions.push(reward_tx);
        let last_hash = self.chain.last().unwrap().hash.clone();
        let block = Block::new(self.chain.len() as u64, transactions, last_hash);
        self.chain.push(block);
        self.pending.clear();
    }

    fn is_valid(&self) -> bool {
        for i in 1..self.chain.len() {
            let prev = &self.chain[i - 1];
            let curr = &self.chain[i];
            if curr.prev_hash != prev.hash || curr.hash != curr.compute_hash() {
                return false;
            }
            for tx in &curr.transactions {
                if !tx.verify() {
                    return false;
                }
            }
        }
        true
    }
}

fn now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

fn main() {
    let wallet_path = "wallet.json";
    let keypair = Keypair::load_from_file(wallet_path).unwrap_or_else(|| {
        let kp = Keypair::generate();
        kp.save_to_file(wallet_path);
        kp
    });

    let address = hex::encode(keypair.public);
    println!("Using wallet address: {}", address);

    let bob = Keypair::generate();
    let bob_addr = hex::encode(bob.public);

    let mut bc = Blockchain::new();

    let mut tx1 = Transaction {
        from: address.clone(),
        to: bob_addr.clone(),
        amount: 10,
        signature: None,
    };
    tx1.sign(&keypair);

    println!("Transaction verified? {}", tx1.verify());
    bc.add_transaction(tx1);
    bc.mine_block(address.clone());

    for block in &bc.chain {
        println!("{:#?}", block);
    }

    println!("Blockchain valid? {}", bc.is_valid());
}
