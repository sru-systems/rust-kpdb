// Copyright (c) 2025 Martijn Rijkeboer <mrr@sru-systems.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Module for the key derivation functions.

use crate::crypto::{aes256, argon2, sha256, sha512};
use crate::types::variant_dictionary::{VariantMap, VariantValue};
use crate::types::{
    Argon2Variant, CompositeKey, Error, HmacKey, KdfConfig, MasterSeed, Result, TransformRounds,
    TransformedKey,
};

/// The UUID of the AES-KDF.
pub const AES_KDF_UUID: [u8; 16] = [
    0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea,
];

/// The UUID of the Argon2 KDF.
pub const ARGON2_UUID: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];

/// The UUID of the Argon2id KDF.
pub const ARGON2ID_UUID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];

/// Parses the KDF parameters from the variant map and returns the configuration,
/// the KDF salt, and the number of transform rounds (for `MetaData.transform_rounds`).
pub fn parse_kdf_parameters(params: &VariantMap) -> Result<(KdfConfig, Vec<u8>, TransformRounds)> {
    let kdf_uuid = match params.get("$UUID") {
        Some(VariantValue::ByteArray(bytes)) if bytes.len() == 16 => {
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(bytes);
            uuid
        }
        _ => return Err(Error::InvalidData),
    };

    let salt = match params.get("S") {
        Some(VariantValue::ByteArray(bytes)) => bytes.clone(),
        _ => return Err(Error::InvalidData),
    };

    if kdf_uuid == AES_KDF_UUID {
        let rounds = match params.get("R") {
            Some(VariantValue::Uint64(rounds)) => *rounds,
            _ => return Err(Error::InvalidData),
        };
        if salt.len() != 32 {
            return Err(Error::InvalidData);
        }
        Ok((KdfConfig::AesKdf, salt, TransformRounds(rounds)))
    } else if kdf_uuid == ARGON2_UUID || kdf_uuid == ARGON2ID_UUID {
        let iterations = match params.get("I") {
            Some(VariantValue::Uint64(iterations)) => *iterations,
            _ => return Err(Error::InvalidData),
        };
        let memory = match params.get("M") {
            Some(VariantValue::Uint64(memory)) => *memory,
            _ => return Err(Error::InvalidData),
        };
        let parallelism = match params.get("P") {
            Some(VariantValue::Uint32(parallelism)) => *parallelism,
            _ => return Err(Error::InvalidData),
        };
        let version = match params.get("V") {
            Some(VariantValue::Uint32(version)) => *version,
            _ => 0x13,
        };
        let variant = if kdf_uuid == ARGON2ID_UUID {
            Argon2Variant::Argon2id
        } else {
            Argon2Variant::Argon2d
        };
        Ok((
            KdfConfig::Argon2 {
                iterations,
                memory,
                parallelism,
                version,
                variant,
            },
            salt,
            TransformRounds(iterations),
        ))
    } else {
        Err(Error::InvalidData)
    }
}

/// Derives the transformed key from the supplied key using the configured KDF.
/// For AES-KDF the supplied rounds are used, for Argon2 the rounds are ignored
/// (iterations from the config are used instead).
pub fn derive_key(
    config: &KdfConfig,
    rounds: &TransformRounds,
    salt: &[u8],
    key: &CompositeKey,
) -> Result<TransformedKey> {
    match *config {
        KdfConfig::AesKdf => derive_aes_key(rounds, salt, key),
        KdfConfig::Argon2 {
            iterations,
            memory,
            parallelism,
            version,
            ref variant,
        } => {
            let raw = argon2::derive(
                &key.unsecure(),
                salt,
                iterations,
                memory,
                parallelism,
                version,
                variant,
            )?;
            Ok(TransformedKey::from_kdf(raw))
        }
    }
}

/// Creates the HMAC key from the master seed and the transformed key.
pub fn hmac_key(master_seed: &MasterSeed, transformed_key: &TransformedKey) -> HmacKey {
    HmacKey(
        sha512::hash(&[&master_seed.0, &transformed_key.unsecure(), &[0x01]])
            .try_into()
            .unwrap(),
    )
}

fn derive_aes_key(
    rounds: &TransformRounds,
    seed: &[u8],
    key: &CompositeKey,
) -> Result<TransformedKey> {
    if seed.len() != 32 {
        return Err(Error::InvalidData);
    }
    let raw_key = key.unsecure();
    let mut output = [0u8; 32];
    output.copy_from_slice(&raw_key[0..32]);
    let ckey: [u8; 32] = seed.try_into().unwrap();
    for _ in 0..rounds.0 {
        aes256::encrypt_blocks(&ckey, &mut output);
    }
    Ok(TransformedKey::from_kdf(sha256::hash(&[&output])))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::types::CompositeKey;
    use crate::types::TransformRounds;
    use crate::types::TransformSeed;
    use crate::types::TransformedKey;

    quickcheck! {
        fn test_rounds_with_transform_rounds_are_identical(data: Vec<u8>) -> bool {
            let composite_key = CompositeKey::from_password("secret");
            let rounds = TransformRounds(6000);
            let transform_seed = TransformSeed([1u8; 32]);

            let transformed_key = TransformedKey::new(&composite_key, &transform_seed, &rounds);

            let from_kdf =
                derive_key(&KdfConfig::AesKdf, &rounds, &transform_seed.0, &composite_key).unwrap();
            from_kdf == transformed_key
        }
    }

    #[test]
    fn test_parse_aes_kdf_parameters_returns_typed_rounds() {
        use crate::types::variant_dictionary::{VariantMap, VariantValue};

        let mut map = VariantMap::new();
        map.insert(String::from("$UUID"), VariantValue::ByteArray(AES_KDF_UUID.to_vec()));
        map.insert(String::from("S"), VariantValue::ByteArray(vec![7u8; 32]));
        map.insert(String::from("R"), VariantValue::Uint64(6000));

        let (config, salt, rounds) = parse_kdf_parameters(&map).unwrap();
        assert_eq!(config, KdfConfig::AesKdf);
        assert_eq!(salt, vec![7u8; 32]);
        assert_eq!(rounds, TransformRounds(6000));
    }

    #[test]
    fn test_parse_argon2_kdf_parameters_returns_typed_rounds() {
        use crate::types::variant_dictionary::{VariantMap, VariantValue};

        let mut map = VariantMap::new();
        map.insert(String::from("$UUID"), VariantValue::ByteArray(ARGON2ID_UUID.to_vec()));
        map.insert(String::from("S"), VariantValue::ByteArray(vec![9u8; 16]));
        map.insert(String::from("I"), VariantValue::Uint64(3));
        map.insert(String::from("M"), VariantValue::Uint64(65536));
        map.insert(String::from("P"), VariantValue::Uint32(2));
        map.insert(String::from("V"), VariantValue::Uint32(0x13));

        let (config, salt, rounds) = parse_kdf_parameters(&map).unwrap();
        assert_eq!(salt, vec![9u8; 16]);
        assert_eq!(rounds, TransformRounds(3));
        match config {
            KdfConfig::Argon2 {
                iterations,
                memory,
                parallelism,
                version,
                variant,
            } => {
                assert_eq!(iterations, 3);
                assert_eq!(memory, 65536);
                assert_eq!(parallelism, 2);
                assert_eq!(version, 0x13);
                assert_eq!(variant, Argon2Variant::Argon2id);
            }
            _ => panic!("expected Argon2 config"),
        }
    }

    #[test]
    fn test_hmac_key_uses_custom_types() {
        use crate::types::MasterSeed;

        let composite_key = CompositeKey::from_password("secret");
        let rounds = TransformRounds(10);
        let seed = vec![1u8; 32];
        let transformed = derive_key(&KdfConfig::AesKdf, &rounds, &seed, &composite_key).unwrap();
        let master_seed = MasterSeed([2u8; 32]);
        let hmac = hmac_key(&master_seed, &transformed);
        // Deterministic and 64 bytes via custom HmacKey type.
        assert_eq!(hmac, hmac_key(&master_seed, &transformed));
        assert_eq!(hmac.0.len(), 64);
    }
}
