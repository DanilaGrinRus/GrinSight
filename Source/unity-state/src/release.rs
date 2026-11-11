//! Signed release checkpoint (stage 4 of the plan).
//!
//! A release directory holds the checkpoint the app ships with:
//!   checkpoint.rwm       header + header-MMR peaks at the checkpoint height
//!   recent-headers.bin   difficulty history before it
//!   release.txt          the signed statement (text, fixed field order)
//!   release.sig          Ed25519 signature over release.txt, hex
//!
//! release.txt binds the network (genesis hash), height, header hash, header
//! MMR root and size, the SHA-256 of both files, a sequence number and the
//! key id. The client accepts it only with a key compiled into the binary
//! (`release-keys.txt`), only if the files match, and never goes back:
//! the sequence must grow, the height must not fall, and the same height must
//! keep the same header (no equivocation). The last accepted release.txt is
//! kept next to the user's checkpoint copy.

use crate::headers::load_checkpoint;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use grin_core::core::hash::Hashed;
use grin_core::global;
use grin_util::ToHex;
use sha2::{Digest, Sha256};
use std::path::Path;

pub(crate) const HEADER: &str = "UNITY-RELEASE-CHECKPOINT/1";
const DOMAIN: &[u8] = b"unity/release-checkpoint/v1\0";

/// Public keys allowed to sign releases: "KEY_ID HEX32" per line, compiled in.
const KEYS: &str = include_str!("../release-keys.txt");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub network: String,
    pub genesis: String,
    pub height: u64,
    pub header_hash: String,
    pub mmr_root: String,
    pub mmr_leaves: u64,
    pub checkpoint_sha256: String,
    pub history_sha256: String,
    pub sequence: u64,
    pub key_id: u32,
}

impl Release {
    pub fn text(&self) -> String {
        format!(
            "{HEADER}\nnetwork={}\ngenesis={}\nheight={}\nheader_hash={}\nmmr_root={}\nmmr_leaves={}\ncheckpoint_sha256={}\nhistory_sha256={}\nsequence={}\nkey_id={}\n",
            self.network, self.genesis, self.height, self.header_hash, self.mmr_root, self.mmr_leaves,
            self.checkpoint_sha256, self.history_sha256, self.sequence, self.key_id
        )
    }

    /// Strict parse: exactly the text `text()` would produce.
    pub fn parse(t: &str) -> Result<Self, String> {
        let mut lines = t.lines();
        if lines.next() != Some(HEADER) {
            return Err("release.txt: bad header".into());
        }
        let mut get = |k: &str| -> Result<String, String> {
            let l = lines.next().ok_or_else(|| format!("release.txt: missing {k}"))?;
            l.strip_prefix(k).and_then(|r| r.strip_prefix('=')).map(|s| s.to_string()).ok_or_else(|| format!("release.txt: expected {k}"))
        };
        let num = |s: String, k: &str| s.parse::<u64>().map_err(|_| format!("release.txt: bad {k}"));
        let r = Release {
            network: get("network")?,
            genesis: get("genesis")?,
            height: num(get("height")?, "height")?,
            header_hash: get("header_hash")?,
            mmr_root: get("mmr_root")?,
            mmr_leaves: num(get("mmr_leaves")?, "mmr_leaves")?,
            checkpoint_sha256: get("checkpoint_sha256")?,
            history_sha256: get("history_sha256")?,
            sequence: num(get("sequence")?, "sequence")?,
            key_id: u32::try_from(num(get("key_id")?, "key_id")?).map_err(|_| "release.txt: bad key_id")?,
        };
        if r.text() != t {
            return Err("release.txt: not in canonical form".into());
        }
        Ok(r)
    }
}

fn payload(text: &str) -> Vec<u8> {
    let mut v = DOMAIN.to_vec();
    v.extend_from_slice(text.as_bytes());
    v
}

fn sha256_file(p: &Path) -> Result<String, String> {
    let b = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(Sha256::digest(&b).to_hex())
}

fn unhex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let s = s.trim();
    if s.len() != N * 2 || !s.is_ascii() {
        return Err(format!("expected {} hex chars", N * 2));
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

pub fn pinned_keys(text: &str) -> Result<Vec<(u32, VerifyingKey)>, String> {
    let mut out = Vec::new();
    for l in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let (id, hex) = l.split_once(char::is_whitespace).ok_or("release-keys: 'ID HEX' per line")?;
        let id: u32 = id.parse().map_err(|_| "release-keys: bad id")?;
        let k = VerifyingKey::from_bytes(&unhex::<32>(hex)?).map_err(|e| format!("release-keys: {e}"))?;
        if k.is_weak() {
            return Err("release-keys: weak key".into());
        }
        out.push((id, k));
    }
    Ok(out)
}

/// Facts of the files in `dir`, checked: the checkpoint loads and validates.
fn describe(dir: &Path) -> Result<Release, String> {
    let cp = dir.join("checkpoint.rwm");
    let v = load_checkpoint(cp.to_str().ok_or("path")?, None)?;
    let f = crate::mmr::CheckpointFile::from_text(cp.to_str().ok_or("path")?)?;
    Ok(Release {
        network: if global::get_chain_type() == global::ChainTypes::Mainnet { "MAINNET".into() } else { "FLOONET".into() },
        genesis: global::get_genesis_block().header.hash().to_hex(),
        height: v.tip.height,
        header_hash: v.tip.hash().to_hex(),
        mmr_root: f.root.to_hex(),
        mmr_leaves: f.acc.leaves,
        checkpoint_sha256: sha256_file(&cp)?,
        history_sha256: sha256_file(&dir.join("recent-headers.bin"))?,
        sequence: 0,
        key_id: 0,
    })
}

/// Rollback / equivocation rules against the last accepted release.
pub fn check_update(old: Option<&Release>, new: &Release) -> Result<(), String> {
    let Some(old) = old else { return Ok(()) };
    if old.genesis != new.genesis {
        return Err("release for another network than the accepted one".into());
    }
    if new.sequence < old.sequence {
        return Err(format!("rollback: sequence {} < accepted {}", new.sequence, old.sequence));
    }
    if new.height < old.height {
        return Err(format!("rollback: height {} < accepted {}", new.height, old.height));
    }
    if new.height == old.height && (new.header_hash != old.header_hash || new.mmr_root != old.mmr_root) {
        return Err("equivocation: another header at the accepted height".into());
    }
    if new.sequence == old.sequence && new != old {
        return Err("same sequence, different release".into());
    }
    Ok(())
}

/// Verify a release directory; `accepted` = last accepted release.txt.
pub fn verify_dir(dir: &Path, accepted: Option<&Path>, keys: &[(u32, VerifyingKey)]) -> Result<Release, String> {
    let text = std::fs::read_to_string(dir.join("release.txt")).map_err(|e| format!("release.txt: {e}"))?;
    let rel = Release::parse(&text)?;
    let sig_hex = std::fs::read_to_string(dir.join("release.sig")).map_err(|e| format!("release.sig: {e}"))?;
    let sig = Signature::from_bytes(&unhex::<64>(&sig_hex)?);
    if keys.is_empty() {
        return Err("no release keys compiled into this build (release-keys.txt is empty)".into());
    }
    let key = keys.iter().find(|(id, _)| *id == rel.key_id).map(|(_, k)| k).ok_or(format!("unknown release key id {}", rel.key_id))?;
    key.verify_strict(&payload(&text), &sig).map_err(|_| "bad release signature".to_string())?;
    let facts = describe(dir)?;
    let mut expect = facts.clone();
    expect.sequence = rel.sequence;
    expect.key_id = rel.key_id;
    if expect != rel {
        let diff: Vec<String> = [
            ("network", &facts.network, &rel.network),
            ("genesis", &facts.genesis, &rel.genesis),
            ("header_hash", &facts.header_hash, &rel.header_hash),
            ("mmr_root", &facts.mmr_root, &rel.mmr_root),
            ("checkpoint_sha256", &facts.checkpoint_sha256, &rel.checkpoint_sha256),
            ("history_sha256", &facts.history_sha256, &rel.history_sha256),
        ]
        .iter()
        .filter(|(_, a, b)| a != b)
        .map(|(k, _, _)| k.to_string())
        .collect();
        return Err(format!("signed release does not match the files: {}", if diff.is_empty() { "height/leaves".into() } else { diff.join(",") }));
    }
    let old = match accepted {
        Some(p) if p.exists() => Some(Release::parse(&std::fs::read_to_string(p).map_err(|e| format!("accepted: {e}"))?)?),
        _ => None,
    };
    check_update(old.as_ref(), &rel)?;
    Ok(rel)
}

/// Developer side: sign the files in `dir` with the seed (32 raw bytes).
pub fn sign_dir(dir: &Path, seed: &Path, key_id: u32, sequence: u64) -> Result<Release, String> {
    let raw = std::fs::read(seed).map_err(|e| format!("seed: {e}"))?;
    let b: [u8; 32] = raw.as_slice().try_into().map_err(|_| "seed file must be exactly 32 raw bytes")?;
    let sk = SigningKey::from_bytes(&b);
    let mut rel = describe(dir)?;
    rel.sequence = sequence;
    rel.key_id = key_id;
    let text = rel.text();
    let sig = sk.sign(&payload(&text));
    std::fs::write(dir.join("release.txt"), &text).map_err(|e| format!("{e}"))?;
    std::fs::write(dir.join("release.sig"), format!("{}\n", sig.to_bytes().to_hex())).map_err(|e| format!("{e}"))?;
    Ok(rel)
}

/// Developer side: a new release key. Refuses to overwrite.
pub fn keygen(out: &Path) -> Result<String, String> {
    use grin_util::secp::rand::Rng;
    if out.exists() {
        return Err(format!("{} exists: not overwriting a release key", out.display()));
    }
    let mut b = [0u8; 32];
    grin_util::secp::rand::thread_rng().fill(&mut b);
    std::fs::write(out, b).map_err(|e| format!("{e}"))?;
    Ok(SigningKey::from_bytes(&b).verifying_key().to_bytes().to_hex())
}

pub fn print(rel: &Release) {
    for l in rel.text().lines().skip(1) {
        let (k, v) = l.split_once('=').unwrap_or((l, ""));
        println!("RELEASE_{}={v}", k.to_uppercase());
    }
}

pub fn compiled_keys() -> Result<Vec<(u32, VerifyingKey)>, String> {
    pinned_keys(KEYS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use grin_core::global::ChainTypes;

    fn rel(seq: u64, h: u64, hash: &str) -> Release {
        Release {
            network: "FLOONET".into(),
            genesis: "g".into(),
            height: h,
            header_hash: hash.into(),
            mmr_root: format!("r{hash}"),
            mmr_leaves: h + 1,
            checkpoint_sha256: "c".into(),
            history_sha256: "d".into(),
            sequence: seq,
            key_id: 1,
        }
    }

    #[test]
    fn text_roundtrip_and_strict() {
        let r = rel(5, 100, "aa");
        assert_eq!(Release::parse(&r.text()).unwrap(), r);
        assert!(Release::parse(&r.text().replace("height=100", "height=0100")).is_err());
        assert!(Release::parse(&(r.text() + "x=1\n")).is_err());
    }

    #[test]
    fn rollback_and_equivocation() {
        let a = rel(5, 100, "aa");
        assert!(check_update(Some(&a), &rel(6, 200, "bb")).is_ok());
        assert!(check_update(Some(&a), &a).is_ok(), "same release again is fine");
        assert!(check_update(Some(&a), &rel(4, 200, "bb")).unwrap_err().contains("sequence"));
        assert!(check_update(Some(&a), &rel(6, 90, "bb")).unwrap_err().contains("height"));
        assert!(check_update(Some(&a), &rel(6, 100, "cc")).unwrap_err().contains("equivocation"));
        assert!(check_update(Some(&a), &rel(5, 200, "bb")).unwrap_err().contains("same sequence"));
        let mut other = rel(6, 200, "bb");
        other.genesis = "x".into();
        assert!(check_update(Some(&a), &other).unwrap_err().contains("network"));
    }

    #[test]
    fn sign_verify_and_tamper() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let dir = std::env::temp_dir().join(format!("unity-rel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Genesis checkpoint (valid by construction) + some history bytes.
        let v = crate::headers::Verifier::from_genesis();
        let g = &v.tip;
        let bytes = grin_core::ser::ser_vec(g, grin_core::ser::ProtocolVersion::local()).unwrap();
        let mut t = format!(
            "RWM1\nheight 0\nhash {}\nheader {}\nleaves {}\nsize {}\nroot {}\n",
            g.hash().to_hex(), bytes.to_hex(), v.mmr.leaves, v.mmr.size, v.mmr.root().to_hex()
        );
        for (pos, height, hash) in &v.mmr.peaks {
            t.push_str(&format!("peak {pos} {height} {}\n", hash.to_hex()));
        }
        std::fs::write(dir.join("checkpoint.rwm"), t).unwrap();
        std::fs::write(dir.join("recent-headers.bin"), b"history").unwrap();
        let seed = dir.join("key.seed");
        let pk = keygen(&seed).unwrap();
        assert!(keygen(&seed).is_err(), "never overwrite a key");
        let keys = pinned_keys(&format!("# test\n7 {pk}\n")).unwrap();
        sign_dir(&dir, &seed, 7, 10).unwrap();
        let r = verify_dir(&dir, None, &keys).unwrap();
        assert_eq!((r.height, r.sequence, r.key_id), (0, 10, 7));
        // Wrong key id / no keys.
        assert!(verify_dir(&dir, None, &pinned_keys(&format!("8 {pk}")).unwrap()).unwrap_err().contains("unknown"));
        assert!(verify_dir(&dir, None, &[]).unwrap_err().contains("no release keys"));
        // Tampered history file.
        std::fs::write(dir.join("recent-headers.bin"), b"history2").unwrap();
        assert!(verify_dir(&dir, None, &keys).unwrap_err().contains("history_sha256"));
        std::fs::write(dir.join("recent-headers.bin"), b"history").unwrap();
        // Tampered statement.
        let txt = std::fs::read_to_string(dir.join("release.txt")).unwrap();
        std::fs::write(dir.join("release.txt"), txt.replace("sequence=10", "sequence=11")).unwrap();
        assert!(verify_dir(&dir, None, &keys).unwrap_err().contains("signature"));
        std::fs::write(dir.join("release.txt"), &txt).unwrap();
        // Rollback against an accepted newer release.
        let acc = dir.join("accepted.txt");
        let mut newer = Release::parse(&txt).unwrap();
        newer.sequence = 20;
        std::fs::write(&acc, newer.text()).unwrap();
        assert!(verify_dir(&dir, Some(&acc), &keys).unwrap_err().contains("rollback"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
