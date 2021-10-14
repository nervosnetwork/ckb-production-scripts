#![allow(unused_imports)]
#![allow(dead_code)]

use ckb_crypto::secp::{Generator, Privkey, Pubkey};
use ckb_error::prelude::thiserror::private::AsDynError;
use ckb_script::TransactionScriptsVerifier;
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    H256,
};
use log::{Level, LevelFilter, Metadata, Record};
use openssl::{sha::Sha256, ssl::ErrorCode};
use rand::{thread_rng, Rng};
use sha3::{digest::generic_array::typenum::private::IsEqualPrivate, Digest, Keccak256};

use misc::{
    assert_script_error, auth_builder, build_resolved_tx, debug_printer, gen_args, gen_consensus,
    gen_tx, gen_tx_env, gen_tx_with_grouped_args, sign_tx, AlgorithmType, Auth, AuthErrorCodeType,
    BitcoinAuth, CKbAuth, CkbMultisigAuth, DogecoinAuth, DummyDataLoader, EntryCategoryType,
    EosAuth, EthereumAuth, TestConfig, TronAuth, MAX_CYCLES,
};
mod misc;

fn verify_unit(config: &TestConfig) -> Result<u64, ckb_error::Error> {
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(&mut data_loader, &config);
    let tx = sign_tx(tx, &config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();

    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    verifier.verify(MAX_CYCLES)
}

fn assert_result_ok(res: Result<u64, ckb_error::Error>, des: &str) {
    assert!(
        res.is_ok(),
        "pass {} verification, des: {}",
        des,
        res.unwrap_err().to_string()
    );
}

fn assert_result_error(res: Result<u64, ckb_error::Error>, des: &str, err_codes: &[i32]) {
    assert!(
        res.is_err(),
        "pass failed {} verification, des: run ok",
        des
    );
    let err_str = res.unwrap_err().to_string();
    let mut is_assert = false;
    for err_code in err_codes {
        if err_str.contains(format!("error code {}", err_code).as_str()) {
            is_assert = true;
            break;
        }
    }

    if !is_assert {
        assert!(false, "pass {} verification, des: {}", des, err_str);
    }
}

fn unit_test_success(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    let config = TestConfig::new(auth, run_type, 1);
    assert_result_ok(verify_unit(&config), "");
}

fn unit_test_multiple_args(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    let config = TestConfig::new(auth, run_type, 5);

    assert_result_ok(verify_unit(&config), "multiple args");
}

fn unit_test_multiple_group(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    let mut data_loader = DummyDataLoader::new();

    let config = TestConfig::new(auth, run_type, 1);

    let mut rng = thread_rng();
    let tx = gen_tx_with_grouped_args(
        &mut data_loader,
        vec![
            (gen_args(&config), 1),
            (gen_args(&config), 1),
            (gen_args(&config), 1),
        ],
        &mut rng,
    );

    let tx = sign_tx(tx, &config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let consensus = gen_consensus();
    let tx_env = gen_tx_env();

    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);

    assert_result_ok(verify_unit(&config), "multiple group");
}

fn unit_test_faileds(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    // public key
    {
        let mut config = TestConfig::new(auth, run_type, 1);
        config.incorrect_pubkey = true;

        assert_result_error(
            verify_unit(&config),
            "public key",
            &[AuthErrorCodeType::Mismatched as i32],
        );
    }

    // sign data
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign = true;
        assert_result_error(
            verify_unit(&config),
            "sign data",
            &[
                AuthErrorCodeType::Mismatched as i32,
                AuthErrorCodeType::InvalidArg as i32,
            ],
        );
    }

    // sign size bigger
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign_size = misc::TestConfigIncorrectSing::Bigger;
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign = true;
        assert_result_error(
            verify_unit(&config),
            "sign size(bigger)",
            &[
                AuthErrorCodeType::Mismatched as i32,
                AuthErrorCodeType::InvalidArg as i32,
            ],
        );
    }

    // sign size smaller
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign_size = misc::TestConfigIncorrectSing::Smaller;
        assert_result_error(
            verify_unit(&config),
            "sign size(smaller)",
            &[
                AuthErrorCodeType::Mismatched as i32,
                AuthErrorCodeType::InvalidArg as i32,
            ],
        );
    }
}

fn unit_test_common_with_auth(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    unit_test_success(auth, run_type);
    unit_test_multiple_args(auth, run_type);
    unit_test_multiple_group(auth, run_type);

    unit_test_faileds(auth, run_type);
}

fn unit_test_common_with_runtype(algorithm_type: AlgorithmType, run_type: EntryCategoryType) {
    let auth = auth_builder(algorithm_type).unwrap();
    unit_test_common_with_auth(&auth, run_type);
}

fn unit_test_common(algorithm_type: AlgorithmType) {
    unit_test_common_with_runtype(algorithm_type, EntryCategoryType::DynamicLinking);
    unit_test_common_with_runtype(algorithm_type, EntryCategoryType::Exec);
}

#[test]
fn ckb_verify() {
    unit_test_common(AlgorithmType::Ckb);
}

#[test]
fn ethereum_verify() {
    unit_test_common(AlgorithmType::Ethereum);
}

#[test]
fn eos_verify() {
    unit_test_common(AlgorithmType::Eos);
}

#[test]
fn tron_verify() {
    unit_test_common(AlgorithmType::Tron);
}

#[test]
fn bitcoin_verify() {
    unit_test_common(AlgorithmType::Bitcoin);
}

#[test]
fn bitcoin_uncompress_verify() {
    let mut auth = misc::BitcoinAuth::new();
    auth.compress = false;
    let auth: Box<dyn Auth> = auth;
    unit_test_common_with_auth(&auth, EntryCategoryType::DynamicLinking);
    unit_test_common_with_auth(&auth, EntryCategoryType::Exec);
}

#[test]
fn bitcoin_pubkey_recid_verify() {
    #[derive(Clone)]
    pub struct BitcoinFailedAuth(BitcoinAuth);
    impl Auth for BitcoinFailedAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            BitcoinAuth::get_btc_pub_key_hash(&self.0.privkey, self.0.compress)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Bitcoin as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            BitcoinAuth::btc_convert_message(message)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            let sign = self
                .0
                .privkey
                .sign_recoverable(&msg)
                .expect("sign")
                .serialize();
            assert_eq!(sign.len(), 65);

            let mut rng = rand::thread_rng();
            let mut recid: u8 = rng.gen_range(0, 4);
            while recid == sign[64] && recid < 31 {
                recid = rng.gen_range(0, 4);
            }
            let mut mark: u8 = sign[64];
            if self.0.compress {
                mark = mark | 4;
            }
            let mut ret = BytesMut::with_capacity(65);
            ret.put_u8(mark);
            ret.put(&sign[0..64]);
            Bytes::from(ret)
        }
    }

    let privkey = Generator::random_privkey();
    let auth: Box<dyn Auth> = Box::new(BitcoinFailedAuth {
        0: BitcoinAuth {
            privkey,
            compress: true,
        },
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver btc",
        &[
            AuthErrorCodeType::Mismatched as i32,
            AuthErrorCodeType::ErrorWrongState as i32,
        ],
    );
}

#[test]
fn dogecoin_verify() {
    unit_test_common(AlgorithmType::Dogecoin);
}

#[test]
fn convert_eth_error() {
    #[derive(Clone)]
    struct EthConverFaileAuth(EthereumAuth);
    impl Auth for EthConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            EthereumAuth::get_eth_pub_key_hash(&self.0.pubkey)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Ethereum as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let eth_prefix: &[u8; 28] = b"\x19Ethereum Signed Xessage:\n32";
            let mut hasher = Keccak256::new();
            hasher.update(eth_prefix);
            hasher.update(message);
            let r = hasher.finalize();
            let ret = H256::from_slice(r.as_slice()).expect("convert_keccak256_hash");
            ret
        }
        fn sign(&self, msg: &H256) -> Bytes {
            EthereumAuth::eth_sign(msg, &self.0.privkey)
        }
    }

    let generator: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    let mut rng = thread_rng();
    let (privkey, pubkey) = generator.generate_keypair(&mut rng);

    let auth: Box<dyn Auth> = Box::new(EthConverFaileAuth {
        0: EthereumAuth { privkey, pubkey },
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver eth",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[test]
fn convert_eos_error() {
    #[derive(Clone)]
    struct EthConverFaileAuth(EosAuth);
    impl Auth for EthConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            EthereumAuth::get_eth_pub_key_hash(&self.0.pubkey)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Eos as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let mut md = Sha256::new();
            md.update(message);
            md.update(&[1, 2, 3]);
            let msg = md.finish();
            H256::from(msg)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            EthereumAuth::eth_sign(msg, &self.0.privkey)
        }
    }

    let generator: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    let mut rng = thread_rng();
    let (privkey, pubkey) = generator.generate_keypair(&mut rng);

    let auth: Box<dyn Auth> = Box::new(EthConverFaileAuth {
        0: EosAuth { privkey, pubkey },
    });
    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver eos",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[test]
fn convert_tron_error() {
    #[derive(Clone)]
    struct TronConverFaileAuth(TronAuth);
    impl Auth for TronConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            EthereumAuth::get_eth_pub_key_hash(&self.0.pubkey)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Tron as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let eth_prefix: &[u8; 24] = b"\x19TRON Signed Xessage:\n32";
            let mut hasher = Keccak256::new();
            hasher.update(eth_prefix);
            hasher.update(message);
            let r = hasher.finalize();
            H256::from_slice(r.as_slice()).expect("convert_keccak256_hash")
        }
        fn sign(&self, msg: &H256) -> Bytes {
            EthereumAuth::eth_sign(msg, &self.0.privkey)
        }
    }

    let generator: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    let mut rng = thread_rng();
    let (privkey, pubkey) = generator.generate_keypair(&mut rng);
    let auth: Box<dyn Auth> = Box::new(TronConverFaileAuth {
        0: TronAuth { privkey, pubkey },
    });
    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver tron",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[test]
fn convert_btc_error() {
    #[derive(Clone)]
    struct BtcConverFaileAuth(BitcoinAuth);
    impl Auth for BtcConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            BitcoinAuth::get_btc_pub_key_hash(&self.0.privkey, self.0.compress)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Bitcoin as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let message_magic = b"\x18Bitcoin Signed Xessage:\n\x40";
            let msg_hex = hex::encode(message);
            assert_eq!(msg_hex.len(), 64);

            let mut temp2: BytesMut = BytesMut::with_capacity(message_magic.len() + msg_hex.len());
            temp2.put(Bytes::from(message_magic.to_vec()));
            temp2.put(Bytes::from(hex::encode(message)));

            let msg = misc::calculate_sha256(&temp2);
            let msg = misc::calculate_sha256(&msg);

            H256::from(msg)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            BitcoinAuth::btc_sign(msg, &self.0.privkey, self.0.compress)
        }
    }

    let privkey = Generator::random_privkey();
    let auth: Box<dyn Auth> = Box::new(BtcConverFaileAuth {
        0: BitcoinAuth {
            privkey,
            compress: true,
        },
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver btc",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[test]
fn convert_doge_error() {
    #[derive(Clone)]
    struct DogeConverFaileAuth(DogecoinAuth);
    impl Auth for DogeConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            BitcoinAuth::get_btc_pub_key_hash(&self.0.privkey, self.0.compress)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Bitcoin as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let message_magic = b"\x18Bitcoin Signed Xessage:\n\x40";
            let msg_hex = hex::encode(message);
            assert_eq!(msg_hex.len(), 64);

            let mut temp2: BytesMut = BytesMut::with_capacity(message_magic.len() + msg_hex.len());
            temp2.put(Bytes::from(message_magic.to_vec()));
            temp2.put(Bytes::from(hex::encode(message)));

            let msg = misc::calculate_sha256(&temp2);
            let msg = misc::calculate_sha256(&msg);

            H256::from(msg)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            BitcoinAuth::btc_sign(msg, &self.0.privkey, self.0.compress)
        }
    }

    let privkey = Generator::random_privkey();
    let auth: Box<dyn Auth> = Box::new(DogeConverFaileAuth {
        0: DogecoinAuth {
            privkey,
            compress: true,
        },
    });

    let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
    assert_result_error(
        verify_unit(&config),
        "failed conver doge",
        &[AuthErrorCodeType::Mismatched as i32],
    );
}

#[derive(Clone)]
pub struct CkbMultisigFailedAuth(CkbMultisigAuth);
impl Auth for CkbMultisigFailedAuth {
    fn get_pub_key_hash(&self) -> Vec<u8> {
        self.0.hash.clone()
    }
    fn get_algorithm_type(&self) -> u8 {
        AlgorithmType::CkbMultisig as u8
    }
    fn sign(&self, msg: &H256) -> Bytes {
        let sign_data = self.0.multickb_sign(msg);
        let mut buf = BytesMut::with_capacity(sign_data.len() + 10);
        buf.put(sign_data);
        buf.put(Bytes::from([0; 10].to_vec()));
        buf.freeze()
    }
    fn get_sign_size(&self) -> usize {
        self.0.get_mulktisig_size()
    }
}

fn unit_test_ckbmultisig(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    unit_test_success(auth, run_type);
    unit_test_multiple_args(auth, run_type);
    unit_test_multiple_group(auth, run_type);

    // public key
    {
        let mut config = TestConfig::new(auth, run_type, 1);
        config.incorrect_pubkey = true;

        assert_result_error(verify_unit(&config), "public key", &[-51]);
    }

    // sign data
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign = true;
        assert_result_error(
            verify_unit(&config),
            "sign data",
            &[-41, -42, -43, -44, -22],
        );
    }

    // sign size bigger
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign_size = misc::TestConfigIncorrectSing::Bigger;
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign = true;
        assert_result_error(
            verify_unit(&config),
            "sign size(bigger)",
            &[-41, -42, -43, -44, -22],
        );
    }

    // sign size smaller
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign_size = misc::TestConfigIncorrectSing::Smaller;
        assert_result_error(
            verify_unit(&config),
            "sign size(smaller)",
            &[-41, -42, -43, -44, -22],
        );
    }

    // cnt_failed
    {
        let auth: Box<dyn Auth> = CkbMultisigAuth::new(2, 3, 1);
        let config = TestConfig::new(&auth, run_type, 1);
        assert_result_error(verify_unit(&config), "cnt failed", &[-43]);
    }

    // cnt_failed
    {
        let auth: Box<dyn Auth> = CkbMultisigAuth::new(2, 2, 4);
        let config = TestConfig::new(&auth, run_type, 1);
        assert_result_error(verify_unit(&config), "require_first_n failed", &[-44]);

        // #define ERROR_INVALID_REQUIRE_FIRST_N -44
    }

    {
        let auth: Box<dyn Auth> = Box::new(CkbMultisigFailedAuth {
            0: {
                let pubkeys_cnt = 2;
                let threshold = 2;
                let require_first_n = 0;
                let (pubkey_data, privkeys) =
                    CkbMultisigAuth::generator_key(pubkeys_cnt, threshold, require_first_n);
                let hash = ckb_hash::blake2b_256(&pubkey_data);
                CkbMultisigAuth {
                    pubkeys_cnt,
                    threshold,
                    pubkey_data,
                    privkeys,
                    hash: hash[0..20].to_vec(),
                }
            },
        });
        let config = TestConfig::new(&auth, run_type, 1);
        assert_result_error(verify_unit(&config), "require_first_n failed", &[-22]);
        // #define ERROR_WITNESS_SIZE -22
    }
}

#[test]
fn ckbmultisig_verify() {
    let auth: Box<dyn Auth> = CkbMultisigAuth::new(2, 2, 1);
    unit_test_ckbmultisig(&auth, EntryCategoryType::DynamicLinking);
    unit_test_ckbmultisig(&auth, EntryCategoryType::Exec);
}

#[test]
fn ckbmultisig_verify_sing_size_failed() {}

#[test]
fn schnorr() {
    {
        let auth = auth_builder(AlgorithmType::SchnorrOrTaproot).unwrap();
        let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
        let verify_result = verify_unit(&config);
        assert_script_error(
            verify_result.unwrap_err(),
            AuthErrorCodeType::NotImplemented,
            "schnorr",
        );
    }
    {
        let auth = auth_builder(AlgorithmType::SchnorrOrTaproot).unwrap();
        let config = TestConfig::new(&auth, EntryCategoryType::Exec, 1);
        let verify_result = verify_unit(&config);
        assert_script_error(
            verify_result.unwrap_err(),
            AuthErrorCodeType::NotImplemented,
            "schnorr",
        );
    }
}

fn unit_test_rsa(auth: &Box<dyn Auth>, run_type: EntryCategoryType) {
    unit_test_success(auth, run_type);
    unit_test_multiple_args(auth, run_type);
    unit_test_multiple_group(auth, run_type);
    // public key
    {
        let mut config = TestConfig::new(auth, run_type, 1);
        config.incorrect_pubkey = true;

        assert_result_error(
            verify_unit(&config),
            "public key",
            &[AuthErrorCodeType::Mismatched as i32],
        );
    }

    // sign data
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign = true;
        assert_result_error(verify_unit(&config), "sign data", &[48, 49]);
        // ERROR_INVALID_MD_TYPE
        // ERROR_INVALID_PADDING
    }

    // sign size bigger
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign_size = misc::TestConfigIncorrectSing::Bigger;
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign = true;
        assert_result_error(verify_unit(&config), "sign size(bigger)", &[41, 48, 49]);
        // ERROR_RSA_INVALID_PARAM2
    }

    // sign size smaller
    {
        let mut config = TestConfig::new(&auth, run_type, 1);
        config.incorrect_sign_size = misc::TestConfigIncorrectSing::Smaller;
        assert_result_error(verify_unit(&config), "sign size(smaller)", &[41, 48, 49]);
    }
}

#[test]
fn rsa_verify() {
    let auth = auth_builder(AlgorithmType::RSA).unwrap();
    unit_test_rsa(&auth, EntryCategoryType::DynamicLinking);
    unit_test_rsa(&auth, EntryCategoryType::Exec);
}

#[test]
fn abnormal_algorithm_type() {
    #[derive(Clone)]
    struct AbnormalAuth {}
    impl misc::Auth for AbnormalAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            [0; 20].to_vec()
        }
        fn get_algorithm_type(&self) -> u8 {
            32
        }
        fn sign(&self, _msg: &H256) -> Bytes {
            Bytes::from([0; 85].to_vec())
        }
    }

    let auth: Box<dyn Auth> = Box::new(AbnormalAuth {});
    {
        let config = TestConfig::new(&auth, EntryCategoryType::DynamicLinking, 1);
        assert_result_error(
            verify_unit(&config),
            "sign size(smaller)",
            &[AuthErrorCodeType::NotImplemented as i32],
        );
    }
    {
        let config = TestConfig::new(&auth, EntryCategoryType::Exec, 1);
        assert_result_error(
            verify_unit(&config),
            "sign size(smaller)",
            &[AuthErrorCodeType::NotImplemented as i32],
        );
    }
}
