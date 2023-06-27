// Copyright (c) 2022-2023 The MobileCoin Foundation

use alloc::string::ToString;
use core::{ops::Deref, str::from_utf8};

use emstr::{helpers::Fractional, EncodeStr};
use prost::{
    bytes::{BufMut, BytesMut},
    Message,
};

use mc_core::account::{RingCtAddress, ShortAddressHash};

use crate::engine::{Error, TokenId};

mod schnorrkel;
pub use schnorrkel::sign_authority;

// Include generated protobuf types
include!(concat!(env!("OUT_DIR"), "/mob.rs"));

/// Per-token information
struct TokenInfo {
    pub id: u64,
    pub scalar: i64,
}

/// Token information for rendering / display
const TOKENS: &[TokenInfo] = &[
    TokenInfo {
        id: 0,
        scalar: SCALAR_MOB,
    },
    TokenInfo {
        id: 1,
        scalar: 1_000_000,
    },
];

const SCALAR_MOB: i64 = 1_000_000_000_000;
const MOB_MAX_SF: usize = 14;

fn get_token_info(token_id: TokenId) -> Option<&'static TokenInfo> {
    TOKENS.iter().find(|&t| t.id == *token_id.deref())
}

// Format helper for values and token types
pub fn fmt_token_val(value: i64, token_id: TokenId, buff: &mut [u8]) -> &str {
    // Match token types
    let scalar = get_token_info(token_id).map(|v| v.scalar).unwrap_or(1);

    // Compute and write value using scalar
    let mut n = match emstr::write!(&mut buff[..], Fractional::<i64>::new(value, scalar)) {
        Ok(v) => v,
        Err(_) => return "ENCODE_ERR",
    };

    // Backtrack and truncate values if max chars is exceeded
    if n > MOB_MAX_SF {
        n = MOB_MAX_SF;
        buff[n] = b'.';
        buff[n + 1] = b'.';
        n += 2;
    }

    // Write token type
    let r = match token_id.deref() {
        // NOTE THAT NAMES STRINGS MUST BE HARDCODED TO AVOID PIC issues with the ledger
        0 => emstr::write!(&mut buff[n..], " MOB"),
        1 => emstr::write!(&mut buff[n..], " eUSD"),
        _ => emstr::write!(&mut buff[n..], " (", token_id.deref(), ')'),
    };
    match r {
        Ok(v) => n += v,
        Err(_) => return "ENCODE_ERR",
    }

    // TODO: ensure values can not be concatenated

    match from_utf8(&buff[..n]) {
        Ok(v) => v,
        Err(_) => "INVALID_UTF8",
    }
}

/// Helper to digest PublicAddress equivalents for [ShortAddressHash]
/// without requiring mc-account-keys (or alloc / bytes).
///
/// This is a re-implementation of the derived [Digestible] for PublicAddress, with tests to ensure these remain in-sync.
#[cfg_attr(feature = "noinline", inline(never))]
pub(crate) fn digest_public_address(
    subaddress: impl RingCtAddress,
    fog_report_url: &str,
    fog_authority_sig: &[u8],
) -> ShortAddressHash {
    use mc_crypto_digestible::{DigestTranscript, Digestible, MerlinTranscript};

    // Setup transcript
    let context = b"mc-address";
    let mut transcript = <MerlinTranscript as DigestTranscript>::new();

    // Write [PublicAddress] equivalent transcript
    transcript.append_agg_header(context, "PublicAddress".as_bytes());
    subaddress
        .view_public_key()
        .inner()
        .append_to_transcript_allow_omit("view_public_key".as_bytes(), &mut transcript);
    subaddress
        .spend_public_key()
        .inner()
        .append_to_transcript_allow_omit("spend_public_key".as_bytes(), &mut transcript);
    fog_report_url.append_to_transcript("fog_report_url".as_bytes(), &mut transcript);
    r#""#.append_to_transcript("fog_report_id".as_bytes(), &mut transcript);
    fog_authority_sig.append_to_transcript("fog_authority_sig".as_bytes(), &mut transcript);
    transcript.append_agg_closer(context, "PublicAddress".as_bytes());

    // Extract digest
    let mut digest = [0u8; 32];
    transcript.extract_digest(&mut digest);

    // Return first 16 bytes as ShortAddressHash
    let hash: [u8; 16] = digest[0..16].try_into().expect("arithmetic error");
    ShortAddressHash::from(hash)
}

/// Helper to b58 encode [PublicAddress] equivalent types without
/// pulling in no-std incompatible `mc_api` dependency.
#[cfg_attr(feature = "noinline", inline(never))]
pub fn b58_encode_public_address<const N: usize>(
    subaddress: impl RingCtAddress,
    fog_report_url: &str,
    fog_authority_sig: &[u8],
) -> Result<heapless::String<N>, Error> {
    use printable_wrapper::*;

    let view_public = subaddress.view_public_key();
    let spend_public = subaddress.spend_public_key();

    // Build printable protobuf wrapper
    // NOTE: this uses prost / is heavily alloc'd under the hood
    let p = PrintableWrapper {
        wrapper: Some(Wrapper::PublicAddress(PublicAddress {
            view_public_key: Some(CompressedRistretto {
                data: view_public.to_bytes().to_vec(),
            }),
            spend_public_key: Some(CompressedRistretto {
                data: spend_public.to_bytes().to_vec(),
            }),
            fog_report_url: fog_report_url.to_string(),
            fog_report_id: "".to_string(),
            fog_authority_sig: fog_authority_sig.to_vec(),
        })),
    };

    // Encode to temporary byte buffer
    // TODO: prefer not to use alloc here but, BufMut seems to be broken for
    // const generic types?!
    let mut data = BytesMut::with_capacity(p.encoded_len() + 4);
    // Pre-allocate space for checksum
    data.put_bytes(0, 4);
    // Encode proto to buffer
    p.encode(&mut data).unwrap();

    // Force drop `p` to free up heap memory
    drop(p);

    // Compute checksum for encoded address
    let checksum = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC)
        .checksum(&data[4..])
        .to_le_bytes();

    // Write checksum to start of buffer
    data[0..4].copy_from_slice(&checksum);

    // Encode address to b58
    let mut buff = HeaplessEncodeTarget::<N>(heapless::String::new());
    let _n = bs58::encode(&data).into(&mut buff).unwrap();

    Ok(buff.0)
}

/// Helper to support bs58 encoding to [heapless::String] types
struct HeaplessEncodeTarget<const N: usize>(heapless::String<N>);

impl<const N: usize> bs58::encode::EncodeTarget for HeaplessEncodeTarget<N> {
    fn encode_with(
        &mut self,
        max_len: usize,
        f: impl for<'a> FnOnce(&'a mut [u8]) -> bs58::encode::Result<usize>,
    ) -> bs58::encode::Result<usize> {
        // Fetch vec and resize
        let v = unsafe { self.0.as_mut_vec() };
        v.resize_default(max_len)
            .map_err(|_| bs58::encode::Error::BufferTooSmall)?;

        // Encode into resized vec
        let n = match f(&mut v[..]) {
            Ok(n) => n,
            Err(e) => {
                // On encoding failure clear vec to avoid returning
                // invalid utf8 string
                v.clear();
                return Err(e);
            }
        };

        // Truncate down to encoded len
        v.truncate(n);

        Ok(n)
    }
}

#[cfg(test)]
mod test {
    use mc_account_keys::AccountKey;
    use mc_transaction_types::TokenId;
    use rand_core::OsRng;

    use super::*;
    use crate::engine::{FogCert, FogId};

    pub(crate) const MAX_LINE_LEN: usize = 20;

    #[test]
    fn fmt_mob() {
        let tests = &[
            (1, "0.000000000001 MOB"),
            (10_000_000, "0.00001 MOB"),
            (10_020_000, "0.00001002 MOB"),
            (10_000_001, "0.000010000001 MOB"),
            (40_000_000, "0.00004 MOB"),
            (40_030_000, "0.00004003 MOB"),
            (-40_000_000, "-0.00004 MOB"),
            (-40_040_000, "-0.00004004 MOB"),
            (400 * SCALAR_MOB, "400 MOB"),
            (400 * SCALAR_MOB + 10_000, "400.00000001 MOB"),
            (400 * SCALAR_MOB + 1, "400.0000000000.. MOB"),
        ];

        for (v, s) in tests {
            let mut buff = [0u8; 32];

            let e = fmt_token_val(*v, TokenId::MOB, &mut buff);

            assert_eq!(&e, s);
            assert!(
                e.len() <= MAX_LINE_LEN,
                "length {} exceeds line limit {} for {}",
                e.len(),
                MAX_LINE_LEN,
                s
            );
        }
    }

    const FOGS: &[FogId] = &[
        FogId::MobMain,
        FogId::MobTest,
        FogId::SignalMain,
        FogId::SignalTest,
    ];

    #[test]
    fn short_address_hash_no_fog() {
        for _i in 0..10 {
            // Create random account without fog info
            let a = AccountKey::random(&mut OsRng {});

            // Test short address hashing
            let h1 = ShortAddressHash::from(&a.default_subaddress());
            let h2 = digest_public_address(a.default_subaddress(), "", &[]);

            assert_eq!(h1, h2);
        }
    }

    #[test]
    fn short_address_hash_with_fog() {
        for f in FOGS {
            for _i in 0..10 {
                // Create random account with fog info
                let a = AccountKey::random(&mut OsRng {}).with_fog(f.url(), "", f.spki());
                let p = a.default_subaddress();

                // Test short address hashing
                let h1 = ShortAddressHash::from(&p);
                let h2 = digest_public_address(
                    &p,
                    p.fog_report_url().unwrap_or(""),
                    p.fog_authority_sig().unwrap_or(&[]),
                );

                assert_eq!(h1, h2);
            }
        }
    }

    const B58_MAX_LEN: usize = 512;

    #[test]
    fn b58_address_no_fog() {
        for _i in 0..10 {
            // Create random account without fog info
            let a = AccountKey::random(&mut OsRng {});
            let p = a.default_subaddress();

            // Local b58 encoding
            let s1 = b58_encode_public_address::<B58_MAX_LEN>(
                &p,
                p.fog_report_url().unwrap_or(""),
                p.fog_authority_sig().unwrap_or(&[]),
            )
            .unwrap();

            // API standard b58 encoding
            let mut wrapper = mc_api::printable::PrintableWrapper::new();
            wrapper.set_public_address((&p).into());
            let s2 = wrapper.b58_encode().unwrap();

            assert_eq!(s1.as_str(), s2.as_str());
        }
    }

    #[test]
    fn b58_address_with_fog() {
        for f in FOGS {
            for _i in 0..10 {
                // Create random account with fog info
                let a = AccountKey::random(&mut OsRng {}).with_fog(f.url(), "", f.spki());
                let p = a.default_subaddress();

                // Local b58 encoding
                let s1 = b58_encode_public_address::<B58_MAX_LEN>(
                    &p,
                    p.fog_report_url().unwrap_or(""),
                    p.fog_authority_sig().unwrap_or(&[]),
                )
                .unwrap();

                // API standard b58 encoding
                let mut wrapper = mc_api::printable::PrintableWrapper::new();
                wrapper.set_public_address((&p).into());
                let s2 = wrapper.b58_encode().unwrap();

                assert_eq!(s1.as_str(), s2.as_str());
            }
        }
    }
}
