#![allow(unused_imports)]
#![allow(dead_code)]

use ckb_crypto::secp::{Generator, Privkey, Pubkey};
use ckb_error::{prelude::thiserror::private::AsDynError, Error};
use ckb_script::TransactionScriptsVerifier;
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    H256,
};
use log::{Level, LevelFilter, Metadata, Record};
use mbedtls::hash::{Md, Type};
use rand::{thread_rng, Rng};
use sha3::{Digest, Keccak256};

use misc::{
    assert_script_error, auth_builder, build_resolved_tx, debug_printer, gen_args, gen_consensus,
    gen_tx, gen_tx_env, gen_tx_with_grouped_args, sign_tx, AlgorithmType, Auth, AuthErrorCodeType,
    BitcoinAuth, CKbAuth, CkbMultisigAuth, DogecoinAuth, DummyDataLoader, EntryCategoryType,
    EosAuth, EthereumAuth, TestConfig, TronAuth, MAX_CYCLES,
};
mod misc;

fn verify_unit(config: &TestConfig) -> Result<u64, Error> {
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

fn unit_test_with_type(t: AlgorithmType, incorrect_pubkey: bool) -> Result<u64, Error> {
    unit_test_with_auth(auth_builder(t).unwrap(), incorrect_pubkey)
}

fn unit_test_get_run_type() -> EntryCategoryType {
    EntryCategoryType::DynamicLinking
}

fn unit_test_with_auth(auth: Box<dyn misc::Auth>, incorrect_pubkey: bool) -> Result<u64, Error> {
    let mut config = TestConfig::new(auth, unit_test_get_run_type(), 1);
    config.incorrect_pubkey = incorrect_pubkey;

    verify_unit(&config)
}

fn unit_test_success(t: AlgorithmType) {
    unit_test_with_type(t, false).expect("pass verification");
}

fn unit_test_failed(t: AlgorithmType) {
    let verify_result = unit_test_with_type(t, true);
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}

#[test]
fn ckb_verify() {
    unit_test_success(AlgorithmType::Ckb);
}

#[test]
fn ckb_verify_pubkey_failed() {
    let auth = auth_builder(AlgorithmType::Ckb).unwrap();
    let mut config = TestConfig::new(auth, unit_test_get_run_type(), 1);
    config.incorrect_pubkey = true;

    let verify_result = verify_unit(&config);
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}

#[test]
fn ckb_verify_msg_failed() {
    unit_test_failed(AlgorithmType::Ckb);
}

#[test]
fn ckb_verify_sign_failed() {
    let auth = auth_builder(AlgorithmType::Ckb).unwrap();
    let mut config = TestConfig::new(auth, unit_test_get_run_type(), 1);
    config.incorrect_sign = true;

    let verify_result = verify_unit(&config);
    misc::assert_script_error_vec(
        verify_result.unwrap_err(),
        &[
            AuthErrorCodeType::Mismatched as i32,
            AuthErrorCodeType::InvalidArg as i32,
        ],
    );
}

#[test]
fn ckb_verify_multiple() {
    let auth = auth_builder(AlgorithmType::Ckb).unwrap();
    let config = TestConfig::new(auth, unit_test_get_run_type(), 5);

    let verify_result = verify_unit(&config);
    verify_result.expect("pass verification");
}

#[test]
fn ckb_verify_multiple_group() {
    let mut data_loader = DummyDataLoader::new();

    let auth = auth_builder(AlgorithmType::Ckb).unwrap();
    let config = TestConfig::new(auth, unit_test_get_run_type(), 1);

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
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn ethereum_verify() {
    unit_test_success(AlgorithmType::Ethereum);
}

#[test]
fn ethereum_verify_failed() {
    unit_test_failed(AlgorithmType::Ethereum);
}

#[test]
fn ethereum_verify_sign_failed() {
    let auth = auth_builder(AlgorithmType::Ethereum).unwrap();
    let mut config = TestConfig::new(auth, unit_test_get_run_type(), 1);
    config.incorrect_sign = true;

    let verify_result = verify_unit(&config);
    misc::assert_script_error_vec(
        verify_result.unwrap_err(),
        &[
            AuthErrorCodeType::Mismatched as i32,
            AuthErrorCodeType::InvalidArg as i32,
        ],
    );
}

#[test]
fn eos_verify() {
    unit_test_success(AlgorithmType::Eos);
}

#[test]
fn eos_verify_failed() {
    unit_test_failed(AlgorithmType::Eos)
}

#[test]
fn tron_verify() {
    unit_test_success(AlgorithmType::Tron);
}

#[test]
fn tron_verify_failed() {
    unit_test_failed(AlgorithmType::Tron);
}

#[test]
fn tron_verify_sign_failed() {
    let auth = auth_builder(AlgorithmType::Tron).unwrap();
    let mut config = TestConfig::new(auth, unit_test_get_run_type(), 1);
    config.incorrect_sign = true;

    let verify_result = verify_unit(&config);
    misc::assert_script_error_vec(
        verify_result.unwrap_err(),
        &[
            AuthErrorCodeType::Mismatched as i32,
            AuthErrorCodeType::InvalidArg as i32,
        ],
    );
}

#[test]
fn bitcoin_verify() {
    unit_test_success(AlgorithmType::Bitcoin);
}

#[test]
fn bitcoin_verify_failed() {
    unit_test_failed(AlgorithmType::Bitcoin);
}

#[test]
fn bitcoin_verify_sign_failed() {
    let auth = auth_builder(AlgorithmType::Bitcoin).unwrap();
    let mut config = TestConfig::new(auth, unit_test_get_run_type(), 1);
    config.incorrect_sign = true;

    let verify_result = verify_unit(&config);
    misc::assert_script_error_vec(
        verify_result.unwrap_err(),
        &[
            AuthErrorCodeType::Mismatched as i32,
            AuthErrorCodeType::InvalidArg as i32,
        ],
    );
}

#[test]
fn bitcoin_verify_uncompress() {
    let mut auth = misc::BitcoinAuth::new();
    auth.compress = false;
    unit_test_with_auth(auth, false).expect("verify btc failed");
}

#[test]
fn dogecoin_verify() {
    unit_test_success(AlgorithmType::Dogecoin);
}

#[test]
fn dogecoin_verify_failed() {
    unit_test_failed(AlgorithmType::Dogecoin);
}

#[test]
fn ckbmultisig_verify() {
    let auth = CkbMultisigAuth::new(2, 2, 1);

    unit_test_with_auth(auth, false).expect("verify btc failed");
}

#[test]
fn ckbmultisig_verify_failed() {
    let auth = CkbMultisigAuth::new(2, 2, 1);

    let verify_result = unit_test_with_auth(auth, true);
    misc::assert_script_error_i(verify_result.unwrap_err(), -51);
    // #define ERROR_MULTSIG_SCRIPT_HASH -51
}

#[test]
fn ckbmultisig_verify_sign_failed() {
    let auth = CkbMultisigAuth::new(2, 2, 1);

    let mut config = TestConfig::new(auth, unit_test_get_run_type(), 1);
    config.incorrect_sign = true;

    let verify_result = verify_unit(&config);
    misc::assert_script_error_i(verify_result.unwrap_err(), -41);
    // #define ERROR_INVALID_RESERVE_FIELD -41
}

#[test]
fn ckbmultisig_verify_cnt_failed() {
    let auth = CkbMultisigAuth::new(2, 3, 1);

    let config = TestConfig::new(auth, unit_test_get_run_type(), 1);

    let verify_result = verify_unit(&config);
    misc::assert_script_error_i(verify_result.unwrap_err(), -43);
    // #define ERROR_INVALID_THRESHOLD -43
}

#[test]
fn ckbmultisig_verify_reqf_failed() {
    let auth = CkbMultisigAuth::new(2, 2, 4);

    let config = TestConfig::new(auth, unit_test_get_run_type(), 1);

    let verify_result = verify_unit(&config);
    misc::assert_script_error_i(verify_result.unwrap_err(), -44);
    // #define ERROR_INVALID_REQUIRE_FIRST_N -44
}

#[test]
fn ckbmultisig_verify_sing_size_failed() {
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

    let auth = Box::new(CkbMultisigFailedAuth {
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

    let verify_result = unit_test_with_auth(auth, true);
    misc::assert_script_error_i(verify_result.unwrap_err(), -22);
    // #define ERROR_WITNESS_SIZE -22
}

#[test]
fn schnorr() {
    let auth = auth_builder(AlgorithmType::SchnorrOrTaproot).unwrap();
    let config = TestConfig::new(auth, unit_test_get_run_type(), 1);
    let verify_result = verify_unit(&config);
    assert_script_error(
        verify_result.unwrap_err(),
        AuthErrorCodeType::NotImplemented,
    );
}

#[test]
fn rsa_verify() {
    unit_test_success(AlgorithmType::RSA);
}

#[test]
fn rsa_verify_failed() {
    unit_test_failed(AlgorithmType::RSA);
}

#[test]
fn rsa_verify_sign_failed() {
    let auth = auth_builder(AlgorithmType::RSA).unwrap();
    let mut config = TestConfig::new(auth, unit_test_get_run_type(), 1);
    config.incorrect_sign = true;

    let verify_result = verify_unit(&config);
    misc::assert_script_error_vec(verify_result.unwrap_err(), &[48, 49]);

    // ERROR_INVALID_MD_TYPE
    // ERROR_INVALID_PADDING
}

#[test]
fn abnormal_algorithm_type() {
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

    let verify_result = unit_test_with_auth(Box::new(AbnormalAuth {}), false);
    assert_script_error(
        verify_result.unwrap_err(),
        AuthErrorCodeType::NotImplemented,
    );
}

#[test]
fn convert_eth_error() {
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

    let auth = Box::new(EthConverFaileAuth {
        0: EthereumAuth { privkey, pubkey },
    });
    let verify_result = unit_test_with_auth(auth, false);
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}

#[test]
fn convert_eos_error() {
    struct EthConverFaileAuth(EosAuth);
    impl Auth for EthConverFaileAuth {
        fn get_pub_key_hash(&self) -> Vec<u8> {
            EthereumAuth::get_eth_pub_key_hash(&self.0.pubkey)
        }
        fn get_algorithm_type(&self) -> u8 {
            AlgorithmType::Eos as u8
        }
        fn convert_message(&self, message: &[u8; 32]) -> H256 {
            let mut msg: [u8; 32] = [0; 32];
            let mut md = Md::new(Type::Sha256).unwrap();
            md.update(message).expect("md sha256 update");
            md.update(&[1, 2, 3]).expect("md sha256 update");
            md.finish(&mut msg).expect("md sha256 finish");
            H256::from(msg)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            EthereumAuth::eth_sign(msg, &self.0.privkey)
        }
    }

    let generator: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    let mut rng = thread_rng();
    let (privkey, pubkey) = generator.generate_keypair(&mut rng);

    let auth = Box::new(EthConverFaileAuth {
        0: EosAuth { privkey, pubkey },
    });
    let verify_result = unit_test_with_auth(auth, false);
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}

#[test]
fn convert_tron_error() {
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
    let auth = Box::new(TronConverFaileAuth {
        0: TronAuth { privkey, pubkey },
    });
    let verify_result = unit_test_with_auth(auth, false);
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}

#[test]
fn convert_btc_error() {
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

            let mut md = Md::new(Type::Sha256).unwrap();
            md.update(temp2.freeze().to_vec().as_slice())
                .expect("md btc failed");
            let mut msg: [u8; 32] = [0; 32];
            md.finish(&mut msg).expect("md btc sha256 finish");

            let mut md = Md::new(Type::Sha256).unwrap();
            md.update(&msg).expect("md btc new message failed");
            md.finish(&mut msg)
                .expect("md btc convert message finish failed");

            H256::from(msg)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            BitcoinAuth::btc_sign(msg, &self.0.privkey, self.0.compress)
        }
    }

    let privkey = Generator::random_privkey();
    let auth = Box::new(BtcConverFaileAuth {
        0: BitcoinAuth {
            privkey,
            compress: true,
        },
    });

    let verify_result = unit_test_with_auth(auth, false);
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}

#[test]
fn convert_doge_error() {
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

            let mut md = Md::new(Type::Sha256).unwrap();
            md.update(temp2.freeze().to_vec().as_slice())
                .expect("md btc failed");
            let mut msg: [u8; 32] = [0; 32];
            md.finish(&mut msg).expect("md btc sha256 finish");

            let mut md = Md::new(Type::Sha256).unwrap();
            md.update(&msg).expect("md btc new message failed");
            md.finish(&mut msg)
                .expect("md btc convert message finish failed");

            H256::from(msg)
        }
        fn sign(&self, msg: &H256) -> Bytes {
            BitcoinAuth::btc_sign(msg, &self.0.privkey, self.0.compress)
        }
    }

    let privkey = Generator::random_privkey();
    let auth = Box::new(DogeConverFaileAuth {
        0: DogecoinAuth {
            privkey,
            compress: true,
        },
    });

    let verify_result = unit_test_with_auth(auth, false);
    assert_script_error(verify_result.unwrap_err(), AuthErrorCodeType::Mismatched);
}
