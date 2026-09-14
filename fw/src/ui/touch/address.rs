// Copyright (c) 2022-2023 The MobileCoin Foundation

//! b58 address display page for touch devices.
//!
//! Built on the non-blocking [`NbglPage`] interface so the app keeps serving
//! APDUs while the address is on screen. Addresses too long for a single
//! screen are split across pages.

use heapless::String;

use ledger_device_sdk::nbgl::{
    Field, NbglPage, NbglPageContent, NbglPageError, NbglPageNav, TagValueList, TOKEN_FIRST_FREE,
};

use ledger_mob_core::{engine::FogId, helpers::b58_encode_public_address};
use mc_core::account::PublicSubaddress;

/// Token reported by the footer quit control
const TOKEN_QUIT: u8 = TOKEN_FIRST_FREE;

/// Token reported by the back arrow in the page header
const TOKEN_BACK: u8 = TOKEN_FIRST_FREE + 1;

/// Token reported by the footer navigation arrows (index is the new page)
const TOKEN_NAV: u8 = TOKEN_FIRST_FREE + 2;

/// Maximum b58 encoded address length (matches `B58_MAX_LEN` in `ledger-mob-core`)
const B58_MAX_LEN: usize = 512;

/// Maximum address characters that fit on one page for each display, with
/// margin for variable glyph widths when wrapping
#[cfg(target_os = "stax")]
const PAGE_MAX_CHARS: usize = 280;
#[cfg(target_os = "flex")]
const PAGE_MAX_CHARS: usize = 200;
#[cfg(target_os = "apex_p")]
const PAGE_MAX_CHARS: usize = 220;

/// Result of handling a touch event on the address page
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AddressEvent {
    /// No change
    None,
    /// Page changed, redraw required
    Update,
    /// User asked to leave the address view
    Exit,
}

/// Non-blocking view of a b58 encoded public address
pub struct AddressView {
    /// Encoded address, retained so pages can be rebuilt on navigation
    value: String<B58_MAX_LEN>,
    /// Number of characters per page
    page_len: usize,
    /// Number of pages (1 when the address fits on a single screen)
    num_pages: usize,
    /// Current page index
    index: usize,
    /// Currently displayed page
    page: NbglPage,
}

impl AddressView {
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn new(address: &PublicSubaddress, fog_id: FogId, fog_authority_sig: &[u8]) -> Self {
        // Encode address to string, falling back to an error marker rather than
        // panicking if the buffer is too small
        let value = match b58_encode_public_address::<B58_MAX_LEN>(
            address,
            fog_id.url(),
            fog_authority_sig,
        ) {
            Ok(v) => v,
            Err(_e) => {
                let mut s = String::new();
                let _ = s.push_str("ENCODE_ERR");
                s
            }
        };

        // Only page when the address does not fit on one screen, splitting
        // evenly so the last page is not a short stub (b58 is ASCII so byte
        // chunking is safe)
        let num_pages = value.len().div_ceil(PAGE_MAX_CHARS).max(1);
        let page_len = value.len().div_ceil(num_pages).max(1);

        let page = build_page(&value, page_len, num_pages, 0);

        Self {
            value,
            page_len,
            num_pages,
            index: 0,
            page,
        }
    }

    /// Draw the current page, returning immediately
    pub fn draw(&mut self) -> Result<(), NbglPageError> {
        self.page.draw()
    }

    /// Check whether the current page still owns the screen
    pub fn is_live(&self) -> bool {
        self.page.is_live()
    }

    /// Handle pending touch events
    pub fn handle_event(&mut self) -> AddressEvent {
        let e = match self.page.take_event() {
            Some(e) => e,
            None => return AddressEvent::None,
        };

        let index = match (e.token, e.index as usize) {
            (TOKEN_QUIT | TOKEN_BACK, _) => return AddressEvent::Exit,
            // NBGL reports the new active page as the nav event index
            (TOKEN_NAV, i) if i < self.num_pages && i != self.index => i,
            _ => return AddressEvent::None,
        };

        // Rebuild for the new page, dropping (and releasing) the old one
        self.index = index;
        self.page = build_page(&self.value, self.page_len, self.num_pages, self.index);

        AddressEvent::Update
    }
}

/// Build the page at `index`, carrying the corresponding chunk of the address
fn build_page(value: &str, page_len: usize, num_pages: usize, index: usize) -> NbglPage {
    let start = index * page_len;
    let end = (start + page_len).min(value.len());

    // NOTE: `TagValueList` copies into owned `CString`s, so the chunk does not
    // need to outlive this call
    let list = TagValueList::new(
        &[Field {
            name: "Address",
            value: &value[start..end],
        }],
        0,
        true,
        true,
    );

    // NOTE: with a single page the button nav draws only the quit footer (no
    // arrows or page indicator). The quit text is required, as a single page
    // with no quit text draws no footer at all, leaving no way off the page.
    let nav = NbglPageNav::with_buttons()
        .pages(index as u8, num_pages as u8)
        .nav_token(TOKEN_NAV)
        .quit("Done", TOKEN_QUIT);

    NbglPage::new(NbglPageContent::TagValueList(list))
        .title("Address")
        .touchable_title(TOKEN_BACK)
        // Clean refresh on first paint avoids e-ink artifacts
        .clean_refresh(index == 0)
        .nav(nav)
}
