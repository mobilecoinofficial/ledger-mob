//! User interface (modules|components) for Ledger devices.

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
