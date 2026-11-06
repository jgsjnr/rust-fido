//! F2 host vectors: official hierarchical-derivation test vectors.
//!
//! The vector-1/2/3/4 chains are asserted verbatim (both the private and
//! the public serialization of every published chain), and the vector-5
//! invalid encodings must all be rejected. Composition coverage derives a
//! master from the official word-list seed and walks the standard
//! account/address paths end to end.

use aegis_fido_core::crypto::Mnemonic24;
use aegis_fido_core::wallet::{
    bitcoin_p2wpkh_address, decode_extended_key, ethereum_address, wallet_address_path,
    CryptoNetwork, DecodedExtendedKey, DerivationPath, ExtendedPrivateKey,
};

fn master_of(seed_hex: &str) -> ExtendedPrivateKey {
    let seed = hex::decode(seed_hex).expect("test seed hex");
    ExtendedPrivateKey::master_from_seed(&seed).expect("test seed derives a master")
}

fn assert_chain(master: &ExtendedPrivateKey, path: &str, xprv: &str, xpub: &str) {
    let parsed: DerivationPath = path.parse().expect("test path parses");
    let node = master.derive_path(&parsed).expect("test path derives");
    assert_eq!(node.to_extended_string(), xprv, "xprv {path}");
    assert_eq!(node.neutered().to_extended_string(), xpub, "xpub {path}");
}

#[test]
fn official_vector_1_all_chains_match() {
    let master = master_of("000102030405060708090a0b0c0d0e0f");
    assert_chain(
        &master,
        "m",
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
    );
    assert_chain(
        &master,
        "m/0'",
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
    );
    assert_chain(
        &master,
        "m/0'/1",
        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
    );
    assert_chain(
        &master,
        "m/0'/1/2'",
        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
        "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
    );
    assert_chain(
        &master,
        "m/0'/1/2'/2",
        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
        "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
    );
    assert_chain(
        &master,
        "m/0'/1/2'/2/1000000000",
        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
    );
}

#[test]
fn official_vector_2_all_chains_match() {
    let master = master_of("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
    assert_chain(
        &master,
        "m",
        "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
        "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
    );
    assert_chain(
        &master,
        "m/0",
        "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
        "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
    );
    assert_chain(
        &master,
        "m/0/2147483647'",
        "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
        "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
    );
    assert_chain(
        &master,
        "m/0/2147483647'/1",
        "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
        "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
    );
    assert_chain(
        &master,
        "m/0/2147483647'/1/2147483646'",
        "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
        "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
    );
    assert_chain(
        &master,
        "m/0/2147483647'/1/2147483646'/2",
        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
        "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
    );
}

#[test]
fn official_vector_3_leading_zeros_roundtrip() {
    let master = master_of("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");
    assert_chain(
        &master,
        "m",
        "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
        "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
    );
    assert_chain(
        &master,
        "m/0'",
        "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
        "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
    );
}

#[test]
fn official_vector_4_leading_zeros_roundtrip() {
    let master = master_of("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678");
    assert_chain(
        &master,
        "m",
        "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
        "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
    );
    assert_chain(
        &master,
        "m/0'",
        "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
        "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
    );
    assert_chain(
        &master,
        "m/0'/1'",
        "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
        "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
    );
}

#[test]
fn official_vector_5_invalid_encodings_rejected() {
    // Every invalid encoding from the vector-5 list must fail closed.
    // (Comments name the violation each string carries.)
    for invalid in [
        // pubkey version / prvkey mismatch
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
        // prvkey version / pubkey mismatch
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
        // invalid pubkey prefix 04
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
        // invalid prvkey prefix 04
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
        // invalid pubkey prefix 01
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
        // invalid prvkey prefix 01
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
        // zero depth with non-zero parent fingerprint (xprv)
        "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
        // zero depth with non-zero parent fingerprint (xpub)
        "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
        // zero depth with non-zero index (xprv)
        "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
        // zero depth with non-zero index (xpub)
        "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
        // unknown extended key version
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
        // unknown extended key version
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
        // private key 0 not in 1..n-1
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
        // private key n not in 1..n-1
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
        // invalid pubkey 0200...0007
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
        // invalid checksum
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
    ] {
        assert!(
            decode_extended_key(invalid).is_err(),
            "must reject {invalid}"
        );
    }
    // Truncated input is rejected before any crypto runs.
    assert!(decode_extended_key("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC").is_err());
    assert!(decode_extended_key("").is_err());
}

#[test]
fn decode_dispatches_on_version_and_roundtrips() {
    let master = master_of("000102030405060708090a0b0c0d0e0f");
    let node = master
        .derive_path(&"m/0'/1".parse().unwrap())
        .expect("derives");
    match decode_extended_key(&node.to_extended_string()).expect("xprv decodes") {
        DecodedExtendedKey::Private(back) => {
            assert_eq!(back.to_extended_bytes(), node.to_extended_bytes())
        }
        DecodedExtendedKey::Public(_) => panic!("xprv must decode as private"),
    }
    match decode_extended_key(&node.neutered().to_extended_string()).expect("xpub decodes") {
        DecodedExtendedKey::Public(back) => {
            assert_eq!(
                back.to_extended_bytes(),
                node.neutered().to_extended_bytes()
            )
        }
        DecodedExtendedKey::Private(_) => panic!("xpub must decode as public"),
    }
}

#[test]
fn word_list_seed_drives_standard_account_paths_end_to_end() {
    // Official word-list vector (zero entropy, passphrase "TREZOR").
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let mnemonic = Mnemonic24::from_phrase(phrase).expect("official phrase parses");
    let seed = mnemonic.to_seed("TREZOR");
    assert_eq!(
        hex::encode(seed),
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
    );
    let master = ExtendedPrivateKey::master_from_seed(&seed).expect("seed derives a master");

    // Segwit account path m/84'/0'/0' and first external address.
    let addr_path = wallet_address_path(CryptoNetwork::Bitcoin, 0, 0, 0).expect("path builds");
    assert_eq!(addr_path.to_string(), "m/84'/0'/0'/0/0");
    let addr_node = master.derive_path(&addr_path).expect("address key derives");
    let address = bitcoin_p2wpkh_address(&addr_node.public_key_compressed());
    assert!(address.starts_with("bc1q"), "segwit address {address}");

    // EVM account path m/44'/60'/0' and first external address.
    let evm_path = wallet_address_path(CryptoNetwork::EthereumEvm, 0, 0, 0).expect("path builds");
    assert_eq!(evm_path.to_string(), "m/44'/60'/0'/0/0");
    let evm_node = master.derive_path(&evm_path).expect("address key derives");
    let evm_address = ethereum_address(&evm_node.public_key_uncompressed_64());
    assert!(evm_address.starts_with("0x"), "evm address {evm_address}");

    // Public derivation from the account extended key matches the private
    // derivation for the non-hardened change/index levels.
    let account_path: DerivationPath = "m/84'/0'/0'".parse().unwrap();
    let account_public = master
        .derive_path(&account_path)
        .expect("account derives")
        .neutered();
    let tail: DerivationPath = "m/0/0".parse().unwrap();
    let via_public = account_public
        .derive_path(&tail)
        .expect("public tail derives");
    assert_eq!(
        via_public.to_extended_bytes(),
        addr_node.neutered().to_extended_bytes()
    );

    // Different seeds never share an address key (derivation isolation).
    let other = ExtendedPrivateKey::master_from_seed(&[0x99u8; 64]).expect("other master");
    let other_node = other.derive_path(&addr_path).expect("other derives");
    assert_ne!(
        other_node.public_key_compressed(),
        addr_node.public_key_compressed()
    );
}
