//! Isolated Goblin message-format research; not a Nostr wallet or transport.
//! The upstream modules have not been changed and retain their own tests.
//! Includes upstream gift-wrap research, but is not a usable messenger.
//! No delivery, identity or Slatepack validity is established here.

pub mod nostr {
    #[cfg(not(target_arch = "wasm32"))]
    pub mod tor_transport;
    #[cfg(not(target_arch = "wasm32"))]
    pub mod contact_session;
    #[cfg(not(target_arch = "wasm32"))]
    pub mod queue_record;
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub mod contact_book_research;
    #[cfg(all(any(windows, target_os = "linux", target_os = "android"), feature = "messaging-identity-research"))]
    pub mod messaging_identity_research;
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub mod queue_store;
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub mod outgoing_resume_research;
    pub mod verified_unwrap;
    #[cfg(all(windows, feature = "windows-vault-queue-research"))]
    pub mod windows_vault_queue_research;
    pub mod protocol;
    pub mod sanitize;
    pub mod wrapv3;
}
