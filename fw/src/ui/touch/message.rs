use ledger_device_sdk::nbgl::NbglStatus;

/// Status message page
///
/// Used to display transient success / error messages
/// (transaction complete, rejected, etc.)
pub struct Message {
    value: &'static str,
    success: bool,
}

impl Message {
    pub fn new(value: &'static str, success: bool) -> Self {
        Self { value, success }
    }

    /// Show a transient (3s) status page, blocking until this is dismissed
    pub fn show_blocking(&self) {
        NbglStatus::new().text(self.value).show(self.success);
    }
}
