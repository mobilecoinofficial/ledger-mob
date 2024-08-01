use core::str::from_utf8;

use emstr::EncodeStr;
use heapless::String;
use rand_core::{CryptoRng, RngCore};

use ledger_device_sdk::buttons::ButtonEvent;
use ledger_device_sdk::ui::{
    bagls::*,
    layout::{Draw, Layout, Location, StringPlace},
    screen_util,
};

use ledger_mob_core::{
    engine::{Driver, Engine, FogId},
    helpers::b58_encode_public_address,
};
use mc_core::account::PublicSubaddress;

use super::{clear_screen, UiResult};

/// Pager for rendering b58 encoded addresses
#[derive(Clone, Debug, PartialEq)]
pub struct Address<const N: usize> {
    value: String<N>,
    page: usize,
    num_pages: usize,
}

const NUM_LINES: usize = 4;
const LINE_LEN: usize = 16;

const PAGE_LEN: usize = LINE_LEN * NUM_LINES;

impl<const N: usize> Address<N> {
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn new(address: &PublicSubaddress, fog_id: FogId, fog_authority_sig: &[u8]) -> Self {
        // Encode address to string
        let value =
            b58_encode_public_address::<N>(address, fog_id.url(), fog_authority_sig).unwrap();

        // Compute number of pages for display
        let num_pages = value.as_bytes().chunks(PAGE_LEN).count();

        // Setup object
        Self {
            value,
            num_pages,
            page: 0,
        }
    }

    pub fn update(&mut self, btn: &ButtonEvent) -> UiResult<()> {
        // Update paging based on button inputs
        match btn {
            // Exit on both buttons pressed/released
            ButtonEvent::BothButtonsRelease => return UiResult::Exit(()),

            // Page forward (increment check to avoid integer overflow per MOB-06.5)
            ButtonEvent::RightButtonRelease if self.page + 1 < self.num_pages => self.page += 1,

            // Page back
            ButtonEvent::LeftButtonRelease if self.page > 0 => self.page -= 1,

            // Otherwise, no change
            _ => return UiResult::None,
        }

        UiResult::Update
    }

    pub fn render<D: Driver, R: RngCore + CryptoRng>(&self, _engine: &Engine<D, R>) {
        // Clear screen
        clear_screen();

        // Show paging arrows
        if self.page != 0 {
            LEFT_ARROW.display();
        }
        if self.page < self.num_pages - 1 {
            RIGHT_ARROW.display();
        }

        // Setup line buffer for display
        let mut line_buff = [""; NUM_LINES + 1];

        // Set title
        let mut title_buff = [0u8; 20];
        line_buff[0] = fmt_title("Address", self.page, self.num_pages, &mut title_buff);

        // Write address line by line
        let page = &self.value[self.page * PAGE_LEN..];
        let mut rem = page.len().min(PAGE_LEN);

        for i in 0..NUM_LINES {
            if rem == 0 {
                continue;
            }

            let n = rem.min(LINE_LEN);
            line_buff[i + 1] = &page[i * LINE_LEN..][..n];

            rem -= n;
        }

        // Render lines
        line_buff.place(Location::Middle, Layout::Centered, false);

        // Update screen
        screen_util::screen_update();
    }
}

fn fmt_title<'a>(name: &str, index: usize, total: usize, buff: &'a mut [u8]) -> &'a str {
    let n = match emstr::write!(&mut buff[..], name, "  (", index + 1, '/', total, ')') {
        Ok(v) => v,
        Err(_) => return "ENCODE_ERR",
    };

    match from_utf8(&buff[..n]) {
        Ok(v) => v,
        Err(_) => "INVALID_UTF8",
    }
}
