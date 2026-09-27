//! User interface (modules|components) for Ledger devices.

use core::str::from_utf8;

use emstr::{helpers::Hex, EncodeStr};

#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
pub mod nano;

#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
pub mod touch;

/// Convert to hex. Returns a static buffer of N bytes
#[inline]
#[allow(unused)]
pub fn to_hex<const N: usize>(data: &[u8]) -> Result<[u8; N], ()> {
    let mut hex = [0u8; N];

    to_hex_slice(data, &mut hex)?;

    Ok(hex)
}

#[inline]
#[allow(unused)]
pub fn to_hex_slice(data: &[u8], buff: &mut [u8]) -> Result<usize, ()> {
    // check buffer length is valid
    if 2 * data.len() > buff.len() {
        return Err(());
    }

    // write hex
    let mut i = 0;
    for c in data {
        let c0 = char::from_digit((c >> 4).into(), 16).unwrap();
        let c1 = char::from_digit((c & 0xf).into(), 16).unwrap();

        buff[i] = c0 as u8;
        buff[i + 1] = c1 as u8;

        i += 2;
    }

    Ok(i)
}

#[inline]
#[allow(unused)]
pub fn to_hex_str<'a>(data: &[u8], buff: &'a mut [u8]) -> Result<&'a str, ()> {
    let n = to_hex_slice(data, buff)?;
    let s = unsafe { core::str::from_utf8_unchecked(&buff[..n]) };
    Ok(s)
}

/// Format a paged heading, eg. `fmt_page("Send", 0, 2, ..)` -> `"Send  (1/2)"`
#[allow(unused)]
pub fn fmt_page<'a>(name: &str, index: usize, total: usize, buff: &'a mut [u8]) -> &'a str {
    let n = match emstr::write!(&mut buff[..], name, "  (", index + 1, '/', total, ')') {
        Ok(v) => v,
        Err(_) => return "ENCODE_ERR",
    };

    match from_utf8(&buff[..n]) {
        Ok(v) => v,
        Err(_) => "INVALID_UTF8",
    }
}

/// Format a short address hash for display, eg. `"(a1b2c3d4...e5f6a7b8)"`
///
/// Used where an address could not be resolved from the summarizer cache.
#[allow(unused)]
pub fn fmt_short_hash<'a>(addr: &[u8], buff: &'a mut [u8]) -> &'a str {
    let n = match emstr::write!(
        &mut buff[..],
        "(",
        Hex(&addr[..4]),
        "...",
        Hex(&addr[addr.len() - 4..]),
        ")"
    ) {
        Ok(v) => v,
        Err(_) => return "ENCODE_ERR",
    };

    match from_utf8(&buff[..n]) {
        Ok(v) => v,
        Err(_) => "INVALID_UTF8",
    }
}
