#![allow(unused)]
// Copyright (c) 2022-2023 The MobileCoin Foundation

use nanos_ui::{
    bagls::*,
    bitmaps,
    layout::{Draw, Layout, Location, StringPlace},
    screen_util,
    ui,
};

const TX_REQ_APPROVE: &str = "Approve Transaction?";
const TX_REQ_DENY: &str = "Reject Transaction?";

/// Clear screen wrapper that works both on hardware and speculos
/// (required as speculos doesn't support the full screen clear syscall,
/// and we want to run _exactly_ the same code on both)
pub fn clear_screen() {
    ui::clear_screen();
}

/// Convert to hex. Returns a static buffer of N bytes
#[inline]
pub fn to_hex<const N: usize>(data: &[u8]) -> Result<[u8; N], ()> {
    let mut hex = [0u8; N];

    to_hex_slice(data, &mut hex)?;

    Ok(hex)
}

#[inline]
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
pub fn to_hex_str<'a>(data: &[u8], buff: &'a mut [u8]) -> Result<&'a str, ()> {
    let n = to_hex_slice(data, buff)?;
    let s = unsafe { core::str::from_utf8_unchecked(&buff[..n]) };
    Ok(s)
}

#[inline]
pub fn show_key(kind: &str, key: &[u8]) {
    let hex1 = to_hex::<64>(key).unwrap();
    let m = core::str::from_utf8(&hex1).unwrap();

    kind.place(Location::Custom(2), Layout::Centered, true);

    for i in 0..4 {
        (&m[i * 16..][..16]).place(Location::Custom(16 + i * 12), Layout::Centered, false);
    }
}

#[inline]
pub fn show_str(kind: &str, s: &str) {
    kind.place(Location::Top, Layout::Centered, true);
    nanos_ui::ui::MessageScroller::new(s).event_loop()
}

#[inline]
pub fn show_var(loc: Location, kind: &str, val: u16) {
    let mut v: [u8; 6] = [b'0', b'x', b'_', b'_', b'_', b'_'];
    to_hex_slice(&val.to_be_bytes(), &mut v[2..]);
    let v = core::str::from_utf8(&v[..]).unwrap();

    kind.place(loc, Layout::LeftAligned, false);
    v.place(loc, Layout::RightAligned, false);
}

/// Tx approve page
pub fn tx_approve_page() {
    TX_REQ_APPROVE.place(Location::Custom(14), Layout::Centered, false);
    CHECKMARK_ICON.shift_v(6).shift_h((128 - 16) / 2).display();
}

/// Tx deny page
pub fn tx_deny_page() {
    TX_REQ_DENY.place(Location::Custom(14), Layout::Centered, false);
    CROSS_ICON.shift_v(6).shift_h((128 - 16) / 2).display();
}
