//! Building the payment core of one profile. Everything here runs on the
//! thread that will own the core.
use crate::profile::{Network, Secrets};
use crate::transport::{HostMailbox, Launcher, SharedReport};
use crate::{ChainPorts, Setup};
use fly_paycore_bridge::ports::{JsonCodec, Ports};
use fly_paycore_bridge::Bridge;
use fly_paycore_guard_os::{OpenError as GuardError, Origin, OsGuard};
use fly_paycore_store::{FsDir, GuardCheck, Identity, RootKey};
use fly_paycore_wallet::Core;
use grin_core::core::hash::Hashed;
use grin_core::global::{self, ChainTypes};
use grin_keychain::{ExtKeychain, Keychain};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// The payment core as the host runs it.
pub type HostCore = Core<FsDir, OsGuard, ExtKeychain>;
/// The bridge as the host runs it.
pub type HostBridge = Bridge<FsDir, OsGuard, ExtKeychain>;

/// Where the files of a profile are.
#[derive(Clone)]
pub(crate) struct Places {
    /// The profile directory.
    pub profile: PathBuf,
    /// Root of the tail guards, outside the profile directory.
    pub guard_root: PathBuf,
    /// The transport program and its settings, if the host has one.
    pub launcher: Option<Launcher>,
    /// The chain program and its settings, if the host has one.
    pub chain: Option<crate::chain::ChainProgram>,
    /// The Tor program for payments to and from the address, if the host
    /// has one.
    pub onion: Option<crate::onion::OnionProgram>,
    /// The key the device keeps for the tail guard, where whoever started
    /// the host has one (`--device-key-stdin`).
    pub device_key: Option<zeroize::Zeroizing<[u8; 32]>>,
}

/// What the tail guard's key is tied to: `os_user` - this user on this
/// machine (Windows); `device` - a key the device keeps, together with the
/// password; `password` - the password alone, so that a profile copied
/// with its guard directory is not noticed as moved.
pub(crate) fn guard_binding(places: &Places) -> &'static str {
    if cfg!(windows) {
        "os_user"
    } else if places.device_key.is_some() {
        "device"
    } else {
        "password"
    }
}

/// Why a profile did not open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Fail {
    /// The tail guard's key was made by another user or machine.
    GuardForeign,
    /// The tail guard's key file is not readable as one.
    GuardDamaged,
    /// The journal of this profile is not where it should be.
    NoJournal,
    /// Anything else; the text names the step, never a secret.
    Other(String),
}

/// What opening found out.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Opened {
    pub guard: GuardCheck,
    pub recovered: bool,
    pub guard_key: Origin,
}

fn other(step: &str) -> Fail {
    Fail::Other(step.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Directory of the journal of the wallet instance.
pub(crate) fn journal_dir(profile: &Path, instance: &[u8; 16]) -> PathBuf {
    profile.join(format!("wallet-{}", hex(instance)))
}

fn chain_dir(profile: &Path, instance: &[u8; 16]) -> PathBuf {
    profile.join(format!("chain-{}", hex(instance)))
}

/// Tor's files for payments to the address: of this wallet alone, so two
/// wallets on one computer do not touch each other's Tor.
fn onion_dir(profile: &Path, instance: &[u8; 16]) -> PathBuf {
    profile.join(format!("onion-{}", hex(instance)))
}

/// Remove everything this wallet keeps on the computer besides the file of
/// its profile: its journal, its tail guard, its chain files and both
/// Tors' files with their keys. Only directories named by the wallet's own
/// number are touched - nothing else in the profile's folder, and nothing
/// of another wallet. What is not there is passed over, so a removal cut
/// short can be done again. The profile's file goes last, by the caller:
/// while it is there the removal can still be asked for and finished.
pub(crate) fn forget(places: &Places, instance: &[u8; 16]) -> std::io::Result<()> {
    let mine = [
        onion_dir(&places.profile, instance),
        transport_dir(&places.profile, instance),
        chain_dir(&places.profile, instance),
        journal_dir(&places.profile, instance),
        places.guard_root.join(hex(instance)),
    ];
    for dir in mine {
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn transport_dir(profile: &Path, instance: &[u8; 16]) -> PathBuf {
    profile.join(format!("transport-{}", hex(instance)))
}

fn make_private_dir(path: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
}

#[cfg(windows)]
fn protector(_places: &Places, _secrets: &Secrets) -> fly_paycore_guard_os::Dpapi {
    fly_paycore_guard_os::Dpapi
}

#[cfg(not(windows))]
fn protector(places: &Places, secrets: &Secrets) -> wrap::Wrap {
    wrap::Wrap {
        profile: secrets.guard_wrap.clone(),
        device: places.device_key.clone(),
    }
}

/// Where the operating system keeps no keys for us, the guard's key is
/// wrapped with a key from the profile. That alone ties the guard to the
/// password and not to the device: a profile copied together with its guard
/// directory is not noticed as moved. Where whoever started the host has a
/// key the device keeps (Android: a key of the Keystore, which does not
/// leave the phone), the guard's key is wrapped with that key over the
/// profile's: a copy on another device does not open, and the wallet says
/// its guard is not its own.
#[cfg(not(windows))]
mod wrap {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use fly_paycore_guard_os::Protector;
    use std::io;
    use zeroize::Zeroizing;

    pub(super) struct Wrap {
        /// The key from the profile.
        pub profile: Zeroizing<[u8; 32]>,
        /// The key the device keeps, if there is one.
        pub device: Option<Zeroizing<[u8; 32]>>,
    }

    fn seal(key: &[u8; 32], plain: &[u8]) -> io::Result<Vec<u8>> {
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).map_err(|_| io::Error::other("no randomness"))?;
        let sealed = XChaCha20Poly1305::new(key.into())
            .encrypt(XNonce::from_slice(&nonce), plain)
            .map_err(|_| io::Error::other("wrapping failed"))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    fn open(key: &[u8; 32], blob: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let (nonce, sealed) = blob
            .split_first_chunk::<24>()
            .ok_or_else(|| io::Error::other("not a wrapped key"))?;
        XChaCha20Poly1305::new(key.into())
            .decrypt(XNonce::from_slice(nonce), sealed)
            .map(Zeroizing::new)
            .map_err(|_| io::Error::other("the key does not unwrap"))
    }

    impl Protector for Wrap {
        fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>> {
            let inner = seal(&self.profile, plain)?;
            match &self.device {
                Some(device) => seal(device, &inner),
                None => Ok(inner),
            }
        }
        fn unprotect(&self, blob: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
            match &self.device {
                Some(device) => open(&self.profile, &open(device, blob)?),
                None => open(&self.profile, blob),
            }
        }
    }
}

fn guard(places: &Places, secrets: &Secrets, reset: bool) -> Result<(OsGuard, Origin), Fail> {
    let dir = places.guard_root.join(hex(&secrets.instance));
    make_private_dir(&dir).map_err(|_| other("the guard directory could not be made"))?;
    let protector = protector(places, secrets);
    match OsGuard::open(&dir, &protector) {
        Ok(found) => Ok(found),
        Err(GuardError::Foreign | GuardError::Damaged) if reset => {
            OsGuard::reset(&dir, &protector).map_err(|_| other("the guard could not be reset"))
        }
        Err(GuardError::Foreign) => Err(Fail::GuardForeign),
        Err(GuardError::Damaged) => Err(Fail::GuardDamaged),
        Err(GuardError::Io(_)) => Err(other("the guard could not be read")),
    }
}

/// Select the chain for this thread and say what the journal is bound to
/// and how long a coinbase output matures.
fn chain(secrets: &Secrets) -> (Identity, u64) {
    let kind = match secrets.network {
        Network::Main => ChainTypes::Mainnet,
        Network::Test => ChainTypes::Testnet,
        Network::Automated => ChainTypes::AutomatedTesting,
    };
    global::set_local_chain_type(kind);
    let mut hash = [0u8; 32];
    let genesis = match secrets.network {
        Network::Main => grin_core::genesis::genesis_main(),
        Network::Test => grin_core::genesis::genesis_test(),
        Network::Automated => grin_core::genesis::genesis_dev(),
    };
    for (to, from) in hash.iter_mut().zip(genesis.hash().as_bytes()) {
        *to = *from;
    }
    (
        Identity {
            network: secrets.network.tag(),
            genesis: hash,
            instance: secrets.instance,
        },
        global::coinbase_maturity(),
    )
}

fn keychain(secrets: &Secrets) -> Result<ExtKeychain, Fail> {
    ExtKeychain::from_seed(&secrets.seed, secrets.network != Network::Main)
        .map_err(|_| other("the seed is not usable"))
}

/// Make the journal of a new profile. Nothing of the profile exists before
/// this, so a failure leaves at most an empty directory nobody refers to.
/// `restored` says that the seed is not new: what it was paid before is
/// searched for (specification 7.19).
pub(crate) fn create(secrets: &Secrets, places: &Places, setup: &Setup, extra: &Value, restored: bool) -> Result<(), Fail> {
    let (identity, maturity) = chain(secrets);
    let keychain = keychain(secrets)?;
    let (guard, _) = guard(places, secrets, false)?;
    let dir = FsDir::new(&journal_dir(&places.profile, &secrets.instance))
        .map_err(|_| other("the wallet directory could not be made"))?;
    let root = RootKey::new(*secrets.root);
    let mut core = Core::create(dir, guard, &root, identity, keychain.clone(), secrets.account, maturity)
        .map_err(|_| other("the journal could not be created"))?;
    if restored {
        core.old_search_start().map_err(|_| other("the journal could not be written"))?;
    }
    if let Some(after_create) = setup.after_create {
        after_create(&mut core, &keychain, extra).map_err(Fail::Other)?;
    }
    Ok(())
}

/// Open the journal of an existing profile and put the bridge around it.
pub(crate) fn open(
    secrets: &Secrets,
    places: &Places,
    setup: &Setup,
    reset_guard: bool,
    report: &SharedReport,
    chain_report: &crate::chain::SharedChainReport,
) -> Result<(HostBridge, Opened), Fail> {
    let (identity, maturity) = chain(secrets);
    let keychain = keychain(secrets)?;
    let journal = journal_dir(&places.profile, &secrets.instance);
    // a journal that is gone is never quietly replaced by an empty one
    if !journal.is_dir() {
        return Err(Fail::NoJournal);
    }
    let (guard, guard_key) = guard(places, secrets, reset_guard)?;
    let dir = FsDir::new(&journal).map_err(|_| other("the wallet directory could not be opened"))?;
    let root = RootKey::new(*secrets.root);
    let (core, found) = Core::open(dir, guard, &root, identity, keychain, maturity).map_err(|e| match e {
        fly_paycore_wallet::CoreError::Open(why) => Fail::Other(format!("the journal did not open: {why}")),
        _ => other("the journal did not open"),
    })?;
    // with a chain program the chain is that process; without one it is
    // what the build of this program provides (the product: nothing known)
    let link = match &places.chain {
        Some(given) => {
            let data = chain_dir(&places.profile, &secrets.instance);
            make_private_dir(&data).map_err(|_| other("the chain directory could not be made"))?;
            let data_dir = data
                .to_str()
                .ok_or_else(|| other("the profile path is not text"))?
                .to_string();
            let launcher = crate::chain::ChainLauncher {
                inside: given.inside,
                program: given.program.clone(),
                peers: given.peers.clone(),
                data_dir,
                network: identity.network,
                genesis: identity.genesis,
                retry: given.retry,
                direct_post: given.direct_post,
                tor_off: given.tor_off,
            };
            Some(crate::chain::Link::start(launcher, chain_report.clone()))
        }
        None => None,
    };
    let ChainPorts {
        broadcaster,
        clock,
        chain,
    } = match &link {
        Some(link) => ChainPorts {
            broadcaster: Box::new(link.clone()),
            clock: Box::new(link.clone()),
            chain: Box::new(link.clone()),
        },
        None => (setup.ports)(),
    };
    let mut bridge = Bridge::new(
        core,
        Ports {
            broadcaster,
            clock,
            chain,
            codec: Box::new(JsonCodec),
            mailbox: None,
        },
    );
    bridge.set_slatepack(true);
    if let Some(link) = link {
        bridge.set_chain_feed(Box::new(link));
    }
    if let Some(launcher) = &places.launcher {
        let data = transport_dir(&places.profile, &secrets.instance);
        make_private_dir(&data).map_err(|_| other("the transport directory could not be made"))?;
        let data_dir = data
            .to_str()
            .ok_or_else(|| other("the profile path is not text"))?
            .to_string();
        let launcher = Launcher {
            data_dir,
            ..launcher.clone()
        };
        let report = report.clone();
        bridge.set_mailbox_factory(Box::new(move |spec| {
            Ok(Box::new(HostMailbox::start(&launcher, spec, report.clone())))
        }));
    }
    if let Some(given) = &places.onion {
        let data = onion_dir(&places.profile, &secrets.instance);
        make_private_dir(&data).map_err(|_| other("the Tor directory could not be made"))?;
        let data_dir = data
            .to_str()
            .ok_or_else(|| other("the profile path is not text"))?
            .to_string();
        let given = crate::onion::OnionProgram { data_dir, ..given.clone() };
        bridge.set_onion_factory(Box::new(move |secret, public| Ok(Box::new(crate::onion::HostOnion::start(&given, secret, public)))));
    }
    Ok((
        bridge,
        Opened {
            guard: found.guard,
            recovered: found.recovered,
            guard_key,
        },
    ))
}
