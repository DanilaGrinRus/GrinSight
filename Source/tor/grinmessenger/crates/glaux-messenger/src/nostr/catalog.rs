// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public, opt-in name catalogue. A match proves key control, not a person's identity.
//! A relay can suppress, retain or replay records: names are not unique.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use super::{binding::NostrBinding, event::Event, NostrKeys, Relay, RelayFilter, hex_encode};
use crate::{Address, error::{Error, Result}};
use std::collections::BTreeMap;

pub const KIND_PROFILE: u32 = 30078;
const DOMAIN: &[u8] = b"grinsight-public-contact-v1\0";
const TAG_DOMAIN: &[u8] = b"grinsight-public-name-v1\0";
const FUTURE_SKEW: u64 = 300;
const MAX_RESULTS: usize = 200;

fn bad(s: &str) -> Error { Error::Crypto(format!("catalog: {s}")) }
/// Case-normalised ASCII names deliberately exclude invisible/confusable Unicode.
pub fn normalize_name(name: &str) -> Result<String> {
    let name = name.trim().trim_start_matches('@').to_ascii_lowercase();
    if !(3..=32).contains(&name.len()) || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-') {
        return Err(bad("name must contain 3–32 ASCII letters, digits, _ or -"));
    }
    Ok(name)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileClaims {
    pub version: u8,
    pub name: String,
    pub wallet_address: String,
    pub binding: NostrBinding,
    pub sequence: u64,
    /// Tombstone revokes this profile by its signing transport key, not copies.
    pub revoked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub claims: ProfileClaims,
    /// Ed25519 signature by the key of wallet_address over wallet_transcript.
    pub wallet_signature: String,
}

/// Feed this domain-separated transcript to the wallet's address signing key.
/// No private key is exported by this API.
pub fn wallet_transcript(claims: &ProfileClaims) -> Result<Vec<u8>> {
    let mut out = DOMAIN.to_vec();
    out.extend(serde_json::to_vec(claims).map_err(|_| bad("invalid profile"))?);
    Ok(out)
}

fn tag(name: &str) -> String {
    let mut h = Sha256::new(); h.update(TAG_DOMAIN); h.update(name.as_bytes()); format!("grinsight-{}", hex_encode(&h.finalize()))
}

/// NIP-33 identifier scoped to an account network and normalized name.
/// Separate values preserve previously published @ names when a phrase is added.
fn profile_identifier(name: &str, network: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"grinsight-public-contact-slot-v2\0");
    h.update(network.as_bytes());
    h.update(b"\0");
    h.update(name.as_bytes());
    format!("grinsight-contact-v2-{}", hex_encode(&h.finalize()))
}

/// A public, non-secret lookup phrase derived only from the public wallet address.
/// It is an index, never an identity assertion; verify the separate comparison code.
pub fn public_search_phrase(wallet_address: &str) -> Result<String> {
    let address = Address::parse(wallet_address).map_err(|_| bad("invalid wallet address"))?;
    if address.to_string() != wallet_address { return Err(bad("noncanonical wallet address")); }
    let mut h = Sha256::new();
    h.update(b"grinsight-public-lookup-phrase-v1\0");
    h.update(wallet_address.as_bytes());
    let digest = h.finalize();
    // 64 short public index words, deliberately not sourced from BIP-39.
    // Six words carry 36 public lookup bits; they do not establish identity.
    const WORDS: [&str; 64] = [
        "ant", "ash", "bay", "bee", "cafe", "cold", "crab", "crow",
        "dew", "dive", "dusk", "elk", "elm", "fern", "fin", "flea",
        "flit", "gull", "halo", "hare", "harp", "haze", "herb", "hive",
        "iris", "jade", "lamb", "lily", "lobe", "loom", "lynx", "mare",
        "mint", "mist", "mole", "moss", "moth", "neon", "owl", "pine",
        "plum", "reef", "reed", "rill", "ruby", "seal", "sky", "slug",
        "soil", "star", "swan", "teal", "toad", "twig", "vase", "vine",
        "wax", "wind", "wren", "yarn", "zest", "zoom", "ibis", "orca",
    ];
    let phrase = digest[..6].iter().map(|b| WORDS[(b & 63) as usize]).collect::<Vec<_>>().join("-");
    debug_assert!(phrase.len() <= 29);
    Ok(phrase)
}

/// Build a replaceable Nostr event only after explicitly opting in to publication.
pub fn signed_event(keys: &NostrKeys, profile: &Profile, now: u64) -> Result<Event> {
    validate_profile(profile, &keys.public_hex(), now)?;
    let claims = &profile.claims;
    let network = Address::parse(&claims.wallet_address)?.hrp().to_string();
    Event::unsigned(keys.public_hex(), now, KIND_PROFILE,
        vec![vec!["d".into(), profile_identifier(&claims.name, &network)], vec!["t".into(), tag(&claims.name)]],
        serde_json::to_string(profile).map_err(|_| bad("profile encoding"))?).sign(keys.secret())
}

pub fn validate_profile(profile: &Profile, author: &str, now: u64) -> Result<()> {
    let c = &profile.claims;
    if c.version != 1 || normalize_name(&c.name)? != c.name || c.binding.transport_key != author { return Err(bad("invalid profile identity")); }
    let owner = Address::parse(&c.binding.owner)?;
    let wallet = Address::parse(&c.wallet_address)?;
    if owner.hrp() != wallet.hrp() || wallet.to_string() != c.wallet_address { return Err(bad("wallet network or address mismatch")); }
    c.binding.verify_update(&owner, now, None).map_err(|_| bad("invalid or expired transport binding"))?;
    let sig = data_encoding::HEXLOWER.decode(profile.wallet_signature.as_bytes()).map_err(|_| bad("invalid wallet signature"))?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| bad("invalid wallet signature"))?;
    if !wallet.verify_bytes(&wallet_transcript(c)?, &sig) { return Err(bad("wallet signature mismatch")); }
    Ok(())
}

/// Search results are candidates, never identity verification; the relay may omit results.
pub fn search(relay: &dyn Relay, query: &str, now: u64) -> Result<Vec<Profile>> {
    let name = normalize_name(query)?;
    let filter = RelayFilter { kinds: vec![KIND_PROFILE], recipient: None, topic: Some(tag(&name)), since: now.saturating_sub(7*24*3600), until: None, limit: MAX_RESULTS };
    let events = relay.query(&filter)?;
    if events.len() > MAX_RESULTS { return Err(bad("too many catalogue results")); }
    let mut latest: BTreeMap<(String, String), (u64, String, Option<Profile>)> = BTreeMap::new();
    for event in events {
        if event.kind != KIND_PROFILE || event.created_at > now.saturating_add(FUTURE_SKEW) || event.content.len() > 8192 || event.verify().is_err() { continue; }
        if !event.tags.iter().any(|t| t.len() == 2 && t[0] == "t" && t[1] == tag(&name)) { continue; }
        let Ok(profile) = serde_json::from_str::<Profile>(&event.content) else { continue };
        let Ok(address) = Address::parse(&profile.claims.wallet_address) else { continue };
        let expected = profile_identifier(&name, address.hrp());
        if !event.tags.iter().any(|t| t.len() == 2 && t[0] == "d" && (t[1] == "grinsight-contact-v1" || t[1] == expected)) { continue; }
        if profile.claims.name != name || validate_profile(&profile, &event.pubkey, now).is_err() { continue; }
        // A valid author can publish the same name independently on mainnet
        // and floonet. A newer record or revocation must not hide the other.
        let identity = (event.pubkey.clone(), address.hrp().to_string());
        match latest.get(&identity) {
            Some((when, id, _)) if *when > event.created_at || (*when == event.created_at && *id <= event.id) => continue,
            _ => {}
        }
        let result = if profile.claims.revoked { None } else { Some(profile) };
        latest.insert(identity, (event.created_at, event.id, result));
    }
    Ok(latest.into_values().filter_map(|(_,_,p)| p).collect())
}

/// Full stable key-set fingerprint used for an explicit identity check mark.
pub fn identity_fingerprint(profile: &Profile) -> String {
    let mut hash=Sha256::new();
    hash.update(b"grinsight-contact-code-v1\0");
    for part in [&profile.claims.wallet_address, &profile.claims.binding.owner, &profile.claims.binding.transport_key] {
        hash.update((part.len() as u32).to_be_bytes()); hash.update(part.as_bytes());
    }
    hex_encode(&hash.finalize())
}

/// Short code is a comparison aid, not an authenticated identity claim.
pub fn comparison_code(profile: &Profile) -> Result<String> {
    let text = identity_fingerprint(profile);
    Ok(format!("{}-{}-{}", &text[..4], &text[4..8], &text[8..12]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Identity, nostr::MemoryRelay};
    use ed25519_dalek::{Signer, SigningKey};
    fn fixture() -> (NostrKeys, Profile) {
        let identity=Identity::from_seed([7;32],"tgrin").unwrap();
        let keys=NostrKeys::from_hex(&format!("{:064x}",1)).unwrap();
        let wallet=SigningKey::from_bytes(&[8;32]);
        let address=Address::from_key("tgrin", wallet.verifying_key().to_bytes()).unwrap().to_string();
        let binding=NostrBinding::create(&identity,&keys.public_hex(),1,1000,1500).unwrap();
        let claims=ProfileClaims { version:1,name:"alice".into(),wallet_address:address,binding,sequence:1,revoked:false };
        let wallet_signature=hex_encode(&wallet.sign(&wallet_transcript(&claims).unwrap()).to_bytes());
        (keys, Profile {claims,wallet_signature})
    }
    #[test] fn wallet_proof_and_public_search() {
        let (keys,p)=fixture(); let relay=MemoryRelay::new();
        relay.publish(&signed_event(&keys,&p,1100).unwrap()).unwrap();
        assert_eq!(search(&relay,"@Alice",1101).unwrap(),vec![p.clone()]);
        let mut forged=p.clone(); forged.claims.wallet_address=Identity::from_seed([9;32],"tgrin").unwrap().address().to_string();
        assert!(signed_event(&keys,&forged,1100).is_err());
        assert!(search(&relay,"alice",1500).unwrap().is_empty());
        assert!(normalize_name("аlice").is_err());
        assert_eq!(comparison_code(&p).unwrap().len(),14);
    }
    #[test] fn public_phrase_is_stable_scoped_and_distinct_from_verification_code() {
        let (_, p) = fixture();
        let address = &p.claims.wallet_address;
        let phrase = public_search_phrase(address).unwrap();
        assert_eq!(phrase, public_search_phrase(address).unwrap());
        assert_eq!(phrase.split('-').count(), 6);
        assert!(phrase.len() <= 29);
        assert_eq!(normalize_name(&phrase).unwrap(), phrase);
        assert_ne!(phrase, comparison_code(&p).unwrap());
        let mainnet = Identity::from_seed([19; 32], "grin").unwrap().address().to_string();
        let floonet = Identity::from_seed([19; 32], "tgrin").unwrap().address().to_string();
        assert_ne!(public_search_phrase(&mainnet).unwrap(), public_search_phrase(&floonet).unwrap());
        assert_ne!(phrase, public_search_phrase(&mainnet).unwrap());
        assert!(public_search_phrase("not an address").is_err());
    }
    #[test] fn separate_replaceable_slots_keep_name_and_phrase_independent() {
        let (keys, p) = fixture();
        let name = &p.claims.name;
        let phrase = public_search_phrase(&p.claims.wallet_address).unwrap();
        assert_ne!(profile_identifier(name, "tgrin"), profile_identifier(&phrase, "tgrin"));
        assert_ne!(profile_identifier(name, "tgrin"), profile_identifier(name, "grin"));
        let mut other = p.clone();
        other.claims.name = phrase.clone();
        other.wallet_signature = hex_encode(&SigningKey::from_bytes(&[8;32]).sign(&wallet_transcript(&other.claims).unwrap()).to_bytes());
        let first = signed_event(&keys, &p, 1100).unwrap();
        let second = signed_event(&keys, &other, 1101).unwrap();
        let tag_d = |e: &Event| e.tags.iter().find(|t| t.len() == 2 && t[0] == "d").unwrap()[1].clone();
        assert_ne!(tag_d(&first), tag_d(&second));
        let relay = MemoryRelay::new();
        relay.publish(&first).unwrap(); relay.publish(&second).unwrap();
        assert_eq!(search(&relay, name, 1102).unwrap(), vec![p]);
        assert_eq!(search(&relay, &phrase, 1102).unwrap(), vec![other]);
    }
    /// Minimal NIP-01 addressable-event relay: same (pubkey, kind, d)
    /// replaces only the corresponding slot; filters are applied afterwards.
    struct AddressableRelay(std::sync::Mutex<std::collections::BTreeMap<(String,u32,String),Event>>);
    impl AddressableRelay { fn new() -> Self { Self(std::sync::Mutex::new(std::collections::BTreeMap::new())) } }
    impl Relay for AddressableRelay {
        fn publish(&self, event: &Event) -> crate::error::Result<()> {
            event.verify()?;
            let d = event.tags.iter().find(|t| t.len() >= 2 && t[0] == "d").map(|t| t[1].clone()).unwrap_or_default();
            let key = (event.pubkey.clone(),event.kind,d);
            let mut slots = self.0.lock().unwrap();
            if slots.get(&key).is_none_or(|old| event.created_at > old.created_at || (event.created_at == old.created_at && event.id < old.id)) { slots.insert(key,event.clone()); }
            Ok(())
        }
        fn query(&self, filter: &RelayFilter) -> crate::error::Result<Vec<Event>> {
            let relay = MemoryRelay::new();
            for event in self.0.lock().unwrap().values() { relay.publish(event)?; }
            relay.query(filter)
        }
    }
    #[test] fn addressable_same_author_name_isolated_by_network_with_legacy_and_revocation() {
        let (keys, floo) = fixture();
        let mut main = floo.clone();
        let wallet = SigningKey::from_bytes(&[8;32]);
        main.claims.wallet_address = Address::from_key("grin", wallet.verifying_key().to_bytes()).unwrap().to_string();
        let identity=Identity::from_seed([7;32],"grin").unwrap();
        main.claims.binding=NostrBinding::create(&identity,&keys.public_hex(),1,1000,1500).unwrap();
        main.wallet_signature = hex_encode(&wallet.sign(&wallet_transcript(&main.claims).unwrap()).to_bytes());
        let relay = AddressableRelay::new();
        let legacy = Event::unsigned(keys.public_hex(), 1099, KIND_PROFILE,
            vec![vec!["d".into(),"grinsight-contact-v1".into()],vec!["t".into(),tag("alice")]],
            serde_json::to_string(&floo).unwrap()).sign(keys.secret()).unwrap();
        relay.publish(&legacy).unwrap();
        relay.publish(&signed_event(&keys, &floo, 1100).unwrap()).unwrap();
        relay.publish(&signed_event(&keys, &main, 1101).unwrap()).unwrap();
        let found = search(&relay,"alice",1102).unwrap();
        assert_eq!(found.len(),2, "one network must not hide the other");
        assert!(found.contains(&floo) && found.contains(&main));
        main.claims.revoked=true;main.claims.sequence=2;
        main.wallet_signature=hex_encode(&wallet.sign(&wallet_transcript(&main.claims).unwrap()).to_bytes());
        relay.publish(&signed_event(&keys,&main,1103).unwrap()).unwrap();
        assert_eq!(search(&relay,"alice",1104).unwrap(),vec![floo]);
    }
    #[test] fn shared_name_different_authors_remain_distinct_and_revocation_is_scoped() {
        let (first_keys, first) = fixture();
        let other_keys = NostrKeys::from_hex(&format!("{:064x}", 2)).unwrap();
        let identity = Identity::from_seed([12;32], "tgrin").unwrap();
        let wallet = SigningKey::from_bytes(&[13;32]);
        let address = Address::from_key("tgrin", wallet.verifying_key().to_bytes()).unwrap().to_string();
        let binding = NostrBinding::create(&identity,&other_keys.public_hex(),1,1000,1500).unwrap();
        let claims = ProfileClaims { version:1,name:"alice".into(),wallet_address:address,binding,sequence:1,revoked:false };
        let mut other = Profile { wallet_signature: hex_encode(&wallet.sign(&wallet_transcript(&claims).unwrap()).to_bytes()), claims };
        let relay=AddressableRelay::new();
        relay.publish(&signed_event(&first_keys,&first,1100).unwrap()).unwrap();
        relay.publish(&signed_event(&other_keys,&other,1101).unwrap()).unwrap();
        let found=search(&relay,"alice",1102).unwrap();
        assert_eq!(found.len(),2); assert!(found.contains(&first) && found.contains(&other));
        other.claims.revoked=true; other.claims.sequence=2;
        other.wallet_signature=hex_encode(&wallet.sign(&wallet_transcript(&other.claims).unwrap()).to_bytes());
        relay.publish(&signed_event(&other_keys,&other,1103).unwrap()).unwrap();
        assert_eq!(search(&relay,"alice",1104).unwrap(),vec![first]);
    }
    #[test] fn old_profile_identifier_remains_searchable() {
        let (keys, p) = fixture();
        let relay = MemoryRelay::new();
        let legacy = Event::unsigned(keys.public_hex(), 1100, KIND_PROFILE,
            vec![vec!["d".into(), "grinsight-contact-v1".into()], vec!["t".into(), tag(&p.claims.name)]],
            serde_json::to_string(&p).unwrap()).sign(keys.secret()).unwrap();
        relay.publish(&legacy).unwrap();
        assert_eq!(search(&relay, "alice", 1101).unwrap(), vec![p]);
    }
    #[test] fn stored_contact_pins_wallet_and_rejects_conflicts() {
        let (_, p)=fixture();
        let root=std::env::temp_dir().join(format!("catalog-pin-{}",uuid::Uuid::new_v4()));
        let book=crate::ContactBook::open(&root,[3;32]).unwrap();
        book.save_catalog_profile(&p,"Alice",1100,true).unwrap();
        let mut changed=p.clone();
        let other=SigningKey::from_bytes(&[9;32]);
        changed.claims.wallet_address=Address::from_key("tgrin",other.verifying_key().to_bytes()).unwrap().to_string();
        changed.claims.sequence=2;
        changed.wallet_signature=hex_encode(&other.sign(&wallet_transcript(&changed.claims).unwrap()).to_bytes());
        assert!(book.save_catalog_profile(&changed,"Alice",1101,true).is_err());
        assert_eq!(book.list().unwrap()[0].catalog_profile.as_ref(),Some(&p));
    }
    #[test] fn verification_mark_requires_explicit_user_confirmation() {
        let (keys,mut p)=fixture();
        let now=crate::nostr::unix_now_secs();
        let identity=Identity::from_seed([7;32],"tgrin").unwrap();
        p.claims.binding=NostrBinding::create(&identity,&keys.public_hex(),1,now,now+500).unwrap();
        p.wallet_signature=hex_encode(&SigningKey::from_bytes(&[8;32]).sign(&wallet_transcript(&p.claims).unwrap()).to_bytes());
        let root=std::env::temp_dir().join(format!("catalog-confirm-{}",uuid::Uuid::new_v4()));
        let book=crate::ContactBook::open(&root,[3;32]).unwrap();
        book.save_catalog_profile(&p,"Alice",now,false).unwrap();
        assert!(book.list().unwrap()[0].identity_verified_fingerprint.is_none());
        book.save_catalog_profile(&p,"Alice",now,true).unwrap();
        assert_eq!(book.list().unwrap()[0].identity_verified_fingerprint.as_deref(),Some(identity_fingerprint(&p).as_str()));
    }
    #[test]
    #[ignore = "read-only network probe"]
    fn live_primal_topic_query() {
        use crate::nostr::WsRelay;
        let url=std::env::var("GS_CATALOG_TEST_RELAY").unwrap_or_else(|_| "wss://relay.primal.net".into());
        let relay=WsRelay::new_direct(&url, NostrKeys::generate().unwrap()).unwrap();
        let result=search(&relay,"grinsight_catalogue_probe_927", crate::nostr::unix_now_secs());
        assert!(result.is_ok(), "public relay query failed: {result:?}");
    }
}
