use ledger_device_sdk::nbgl::NbglChoice;

pub struct SyncRequest {
    choice: NbglChoice<'static>,
}

impl SyncRequest {
    pub fn new() -> Self {
        Self {
            choice: NbglChoice::new(),
        }
    }

    pub fn show_blocking(&self) -> bool {
        self.choice.show(
            "Sync Wallet?",
            "Allow the connected application to retrieve account balances",
            "Sync",
            "Reject",
        )
    }
}
