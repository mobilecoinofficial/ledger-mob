// Copyright (c) 2022-2023 The MobileCoin Foundation

use core::{ops::Deref, str::from_utf8};

use emstr::{helpers::Fractional, EncodeStr};

use crate::engine::TokenId;

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
    let r = match token_id {
        // NOTE THAT NAMES STRINGS MUST BE HARDCODED TO AVOID PIC issues with the ledger
        TokenId::MOB => emstr::write!(&mut buff[n..], " MOB"),
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

#[cfg(test)]
mod test {
    use mc_transaction_types::TokenId;

    use super::{fmt_token_val, SCALAR_MOB};

    const MAX_LINE_LEN: usize = 20;

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
}
