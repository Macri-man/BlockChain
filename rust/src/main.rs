use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
struct Keypair {
    secret: Scalar,
    public: RistrettoPoint,
}

impl Keypair {
    fn generate() -> Self {
        let mut csprng = OsRng;
        let secret = Scalar::random(&mut csprng);
        let public = secret * RISTRETTO_BASEPOINT_POINT;
        Keypair { secret, public }
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
        hasher.update(key.public.compress().as_bytes());
        hasher.update(msg);
        let h = Scalar::from_hash(hasher);

        let s = k + h * key.secret;

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
        let s = match Scalar::from_canonical_bytes(self.s) {
            Some(s) => s,
            None => return false,
        };

        let mut hasher = Sha512::new();
        hasher.update(&self.R);
        hasher.update(pubkey.compress().as_bytes());
        hasher.update(msg);
        let h = Scalar::from_hash(hasher);

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
        let pubkey_bytes = match hex::decode(&self.from) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let pubkey = match CompressedRistretto::from_slice(&pubkey_bytes).decompress() {
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
        let mut hash = String::new();
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
    let alice = Keypair::generate();
    let bob = Keypair::generate();

    let alice_addr = hex::encode(alice.public.compress().to_bytes());
    let bob_addr = hex::encode(bob.public.compress().to_bytes());

    let mut bc = Blockchain::new();

    let mut tx1 = Transaction {
        from: alice_addr.clone(),
        to: bob_addr.clone(),
        amount: 10,
        signature: None,
    };
    tx1.sign(&alice);

    println!("Transaction verified? {}", tx1.verify());
    bc.add_transaction(tx1);
    bc.mine_block(alice_addr.clone());

    for block in &bc.chain {
        println!("{:#?}", block);
    }

    println!("Blockchain valid? {}", bc.is_valid());
}
