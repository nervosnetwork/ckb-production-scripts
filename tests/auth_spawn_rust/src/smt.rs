use ckb_hash::{Blake2b, Blake2bBuilder};
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::traits::Hasher;
use sparse_merkle_tree::{SparseMerkleTree, H256};

pub struct CKBBlake2bHasher(Blake2b);
pub const BLAKE2B_KEY: &[u8] = &[];
pub const BLAKE2B_LEN: usize = 32;
pub const PERSONALIZATION: &[u8] = b"ckb-default-hash";
use lazy_static::lazy_static;

lazy_static! {
    pub static ref SMT_EXISTING: H256 = H256::from([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]);
}

impl Default for CKBBlake2bHasher {
    fn default() -> Self {
        let blake2b = Blake2bBuilder::new(BLAKE2B_LEN)
            .personal(PERSONALIZATION)
            .key(BLAKE2B_KEY)
            .build();
        CKBBlake2bHasher(blake2b)
    }
}

impl Hasher for CKBBlake2bHasher {
    fn write_h256(&mut self, h: &H256) {
        self.0.update(h.as_slice());
    }
    fn finish(self) -> H256 {
        let mut hash = [0u8; 32];
        self.0.finalize(&mut hash);
        hash.into()
    }
    fn write_byte(&mut self, b: u8) {
        self.0.update(&[b][..]);
    }
}

pub type SMT = SparseMerkleTree<CKBBlake2bHasher, H256, DefaultStore<H256>>;

pub fn new_smt(pairs: Vec<(H256, H256)>) -> SMT {
    let mut smt = SMT::default();
    for (key, value) in pairs {
        smt.update(key, value).unwrap();
    }
    smt
}

// return smt root and proof
pub fn build_tree(hashes: &Vec<[u8; 32]>) -> (H256, Vec<u8>) {
    let existing_pairs: Vec<(H256, H256)> = hashes
        .clone()
        .into_iter()
        .map(|hash| (hash.into(), SMT_EXISTING.clone()))
        .collect();
    let mut pairs = vec![];
    pairs.extend(existing_pairs.clone());

    let smt = new_smt(pairs);
    let root = smt.root();

    let keys: Vec<H256> = existing_pairs.clone().into_iter().map(|(k, _)| k).collect();
    let proof = smt.merkle_proof(keys.clone()).expect("gen proof");
    let compiled_proof = proof.clone().compile(keys.clone()).expect("compile proof");
    let _ = compiled_proof
        .verify::<CKBBlake2bHasher>(root, existing_pairs.clone())
        .expect("verify compiled proof");
    return (root.clone(), compiled_proof.into());
}
