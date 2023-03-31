// Copyright (c) 2022-2023 The MobileCoin Foundation

use core::mem::MaybeUninit;

use mc_core::{
    account::PublicSubaddress,
    keys::{RootViewPrivate, SubaddressSpendPrivate},
};
use mc_transaction_types::BlockVersion;

use ledger_mob_apdu::tx::TxOnetimeKey;

use super::Error;

#[cfg(feature = "mlsag")]
use super::ring::RingSigner;

#[cfg(feature = "summary")]
use super::{summary::Summarizer, MAX_RECORDS};

#[cfg(feature = "ident")]
use super::ident::Ident;

pub struct Function {
    inner: FunctionType,
}

impl Default for Function {
    fn default() -> Self {
        Self {
            inner: FunctionType::None,
        }
    }
}

/// Enum for internal state machines to allow stack to be shared between functions
/// and encapsulate [out-pointer](https://doc.rust-lang.org/core/mem/union.MaybeUninit.html#out-pointers) usage to mitigate stack issues
#[allow(clippy::large_enum_variant)]
enum FunctionType {
    None,

    #[cfg(feature = "summary")]
    Summarize(MaybeUninit<Summarizer<MAX_RECORDS>>),

    #[cfg(feature = "mlsag")]
    RingSign(MaybeUninit<RingSigner>),

    #[cfg(feature = "ident")]
    Ident(Ident),
}

impl Default for FunctionType {
    fn default() -> Self {
        Self::None
    }
}

impl Function {
    /// Create a new / empty function context
    pub const fn new() -> Self {
        Self {
            inner: FunctionType::None,
        }
    }

    /// Setup ring-signer context
    ///
    /// this uses out-pointer based init to avoid stack allocation
    /// see: https://doc.rust-lang.org/core/mem/union.MaybeUninit.html#out-pointers
    #[cfg(feature = "mlsag")]
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn ring_signer_init(
        &mut self,
        ring_size: usize,
        real_index: usize,
        root_view_private: &RootViewPrivate,
        subaddress_spend_private: &SubaddressSpendPrivate,
        value: u64,
        message: &[u8],
        token_id: u64,
        onetime_private_key: Option<TxOnetimeKey>,
    ) -> Result<&mut RingSigner, Error> {
        // Clear function prior to init (executes drop)
        self.clear();

        // Setup uninitialised context
        self.inner = FunctionType::RingSign(MaybeUninit::uninit());

        // Return uninitialised context pointer
        let p = match &mut self.inner {
            FunctionType::RingSign(s) => s.as_mut_ptr(),
            _ => unreachable!(),
        };

        // Initialise ring signer
        if let Err(e) = unsafe {
            RingSigner::init(
                p,
                ring_size,
                real_index,
                root_view_private,
                subaddress_spend_private,
                value,
                message,
                token_id,
                onetime_private_key,
            )
        } {
            // Clear context and return error
            self.clear();

            return Err(e);
        }

        // Return initialised ring signer
        Ok(unsafe { &mut *p })
    }

    /// Fetch ring signer context
    #[cfg(feature = "mlsag")]
    pub fn ring_signer(&mut self) -> Option<&mut RingSigner> {
        match &mut self.inner {
            FunctionType::RingSign(s) => Some(unsafe { &mut *s.as_mut_ptr() }),
            _ => None,
        }
    }

    /// Fetch ring signer context
    #[cfg(feature = "mlsag")]
    pub fn ring_signer_ref(&self) -> Option<&RingSigner> {
        match &self.inner {
            FunctionType::RingSign(s) => Some(unsafe { &*s.as_ptr() }),
            _ => None,
        }
    }

    /// Setup summarizer context
    ///
    /// this uses out-pointer based init to avoid stack allocation
    /// see: https://doc.rust-lang.org/core/mem/union.MaybeUninit.html#out-pointers
    #[cfg(feature = "summary")]
    #[cfg_attr(feature = "noinline", inline(never))]
    pub fn summarizer_init(
        &mut self,
        message: &[u8; 32],
        block_version: BlockVersion,
        num_outputs: usize,
        num_inputs: usize,
        view_private_key: &RootViewPrivate,
        change_subaddress: &PublicSubaddress,
    ) -> &mut Summarizer<MAX_RECORDS> {
        // Clear function prior to init (executes drop)

        self.clear();

        // Setup uninitialised context
        self.inner = FunctionType::Summarize(MaybeUninit::uninit());

        // Return uninitialised context pointer
        let p = match &mut self.inner {
            FunctionType::Summarize(s) => s.as_mut_ptr(),
            _ => unreachable!(),
        };

        // Initialise summarizer memory
        unsafe {
            Summarizer::init(
                p,
                message,
                block_version,
                num_outputs,
                num_inputs,
                view_private_key,
                change_subaddress,
            )
        };

        // Return summarizer context
        unsafe { &mut *p }
    }

    /// Fetch summarizer context
    #[cfg(feature = "summary")]
    pub fn summarizer(&mut self) -> Option<&mut Summarizer<MAX_RECORDS>> {
        match &mut self.inner {
            FunctionType::Summarize(s) => Some(unsafe { &mut *s.as_mut_ptr() }),
            _ => None,
        }
    }

    /// Fetch summarizer context
    #[cfg(feature = "summary")]
    pub fn summarizer_ref(&self) -> Option<&Summarizer<MAX_RECORDS>> {
        match &self.inner {
            FunctionType::Summarize(s) => Some(unsafe { &*s.as_ptr() }),
            _ => None,
        }
    }

    /// Initialise identity function
    #[cfg(feature = "ident")]
    pub fn ident_init(
        &mut self,
        identity_index: u32,
        uri: &str,
        challenge: &[u8],
    ) -> Result<&mut Ident, Error> {
        // Clear function prior to init (executes drop)
        self.clear();

        // Setup ident context
        self.inner = FunctionType::Ident(Ident::new(identity_index, uri, challenge)?);

        // Return ident context
        match &mut self.inner {
            FunctionType::Ident(s) => Ok(s),
            _ => unreachable!(),
        }
    }

    /// Fetch ident context
    #[cfg(feature = "ident")]
    pub fn ident_ref(&self) -> Option<&Ident> {
        match &self.inner {
            FunctionType::Ident(s) => Some(s),
            _ => None,
        }
    }

    /// Clear context, executing drop if required
    pub fn clear(&mut self) {
        match &mut self.inner {
            #[cfg(feature = "mlsag")]
            FunctionType::RingSign(s) => unsafe {
                s.assume_init_drop();
            },
            #[cfg(feature = "summary")]
            FunctionType::Summarize(s) => unsafe { s.assume_init_drop() },
            _ => (),
        }

        self.inner = FunctionType::None;
    }
}
