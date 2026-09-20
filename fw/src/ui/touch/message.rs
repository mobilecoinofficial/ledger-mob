use ledger_device_sdk::nbgl::{
    CenteredInfo, CenteredInfoStyle, NbglPage, NbglPageContent, NbglPageError, NbglPageNav,
    TOKEN_FIRST_FREE,
};

use crate::consts::{STATUS_FAILURE, STATUS_SUCCESS};

/// Token reported by the message close (footer) button
const TOKEN_CLOSE: u8 = TOKEN_FIRST_FREE;

/// Status message page
///
/// Used to display success / error messages (transaction complete, rejected, etc.)
///
/// This uses the non-blocking [NbglPage] API, so the application continues to
/// process events while the message is displayed. The page is dismissed on touch
/// (see [Message::take_dismiss]) or by the message timeout in `main.rs`.
pub struct Message {
    /// Page state, this must be kept alive while the page is displayed
    /// as NBGL holds pointers into this object
    page: NbglPage,
}

impl Message {
    pub fn new(value: &'static str, success: bool) -> Self {
        let icon = match success {
            true => &STATUS_SUCCESS,
            false => &STATUS_FAILURE,
        };

        let info = CenteredInfo::new(
            value,
            "",
            "",
            Some(icon),
            false,
            CenteredInfoStyle::LargeCaseBoldInfo,
            0,
        );

        let page = NbglPage::new(NbglPageContent::CenteredInfo(info))
            .clean_refresh(true)
            // NOTE: `NAV_WITH_TAP` only makes the main area tappable when `nextPageText`
            // is set (not exposed by the SDK), so a close button is used in the footer.
            .nav(NbglPageNav::with_tap().quit("Close", TOKEN_CLOSE));

        Self { page }
    }

    /// Draw the page (if not already displayed), returning immediately
    pub fn draw(&mut self) -> Result<(), NbglPageError> {
        match self.page.is_live() {
            true => Ok(()),
            false => self.page.draw(),
        }
    }

    /// Check for touch events, returning true if the page should be dismissed
    pub fn take_dismiss(&mut self) -> bool {
        self.page.take_event().is_some()
    }
}
