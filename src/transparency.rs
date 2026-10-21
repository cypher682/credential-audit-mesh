use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::credential::Credential;

type Hash = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    pub index: u64,
    pub credential_hash: String,
    pub issuer: String,
    pub subject_hash: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TreeHead {
    pub tree_size: u64,
    pub root_hash: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InclusionProof {
    pub entry: LogEntry,
    pub leaf_hash: String,
    pub tree_size: u64,
    pub root_hash: String,
    pub inclusion_proof: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub first_size: u64,
    pub second_size: u64,
    pub first_root: String,
    pub second_root: String,
    pub proof: Vec<String>,
}

pub struct TransparencyLog {
    entries: Vec<LogEntry>,
    leaves: Vec<Hash>,
    roots: Vec<Hash>,
    journal: Option<File>,
}

impl Default for TransparencyLog {
    fn default() -> Self {
        Self::new()
    }
}

impl TransparencyLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            leaves: Vec::new(),
            roots: vec![empty_root()],
            journal: None,
        }
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("create log directory: {err}"))?;
        }

        let journal = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)
            .map_err(|err| format!("open transparency log: {err}"))?;
        let reader = File::open(path).map_err(|err| format!("read transparency log: {err}"))?;

        let mut log = Self {
            entries: Vec::new(),
            leaves: Vec::new(),
            roots: vec![empty_root()],
            journal: Some(journal),
        };
        for (line_number, line) in BufReader::new(reader).lines().enumerate() {
            let line = line.map_err(|err| format!("read transparency log: {err}"))?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: LogEntry = serde_json::from_str(&line)
                .map_err(|err| format!("invalid log entry on line {}: {err}", line_number + 1))?;
            if entry.index != log.tree_size() {
                return Err(format!(
                    "invalid log entry index {} on line {}, expected {}",
                    entry.index,
                    line_number + 1,
                    log.tree_size()
                ));
            }
            log.push_entry(entry)
                .map_err(|err| format!("invalid log entry on line {}: {err}", line_number + 1))?;
        }

        Ok(log)
    }

    pub fn tree_size(&self) -> u64 {
        self.entries.len() as u64
    }

    pub fn head(&self) -> TreeHead {
        TreeHead {
            tree_size: self.tree_size(),
            root_hash: encode_hash(*self.roots.last().expect("root history")),
        }
    }

    pub fn entry(&self, index: u64) -> Option<&LogEntry> {
        self.entries.get(index as usize)
    }

    pub fn append(&mut self, credential: &Credential) -> Result<InclusionProof, String> {
        let entry = LogEntry {
            index: self.tree_size(),
            credential_hash: credential.digest().map_err(|err| err.to_string())?,
            issuer: credential.issuer.clone(),
            subject_hash: hash_b64(credential.subject.as_bytes()),
            issued_at: credential.issued_at,
            expires_at: credential.expires_at,
            key_id: credential.key_id.clone(),
        };
        let canonical =
            serde_jcs::to_vec(&entry).map_err(|err| format!("canonicalize log entry: {err}"))?;
        let leaf = hash_leaf(&canonical);

        if let Some(journal) = self.journal.as_mut() {
            journal
                .write_all(&canonical)
                .and_then(|_| journal.write_all(b"\n"))
                .and_then(|_| journal.sync_data())
                .map_err(|err| format!("append transparency log: {err}"))?;
        }
        self.entries.push(entry);
        self.leaves.push(leaf);
        self.roots.push(merkle_root(&self.leaves));

        self.inclusion(entry_index(&self.entries))
            .ok_or_else(|| "failed to build inclusion proof".into())
    }

    fn push_entry(&mut self, entry: LogEntry) -> Result<(), String> {
        let canonical =
            serde_jcs::to_vec(&entry).map_err(|err| format!("canonicalize log entry: {err}"))?;
        self.entries.push(entry);
        self.leaves.push(hash_leaf(&canonical));
        self.roots.push(merkle_root(&self.leaves));
        Ok(())
    }

    pub fn inclusion(&self, index: u64) -> Option<InclusionProof> {
        let index = usize::try_from(index).ok()?;
        let entry = self.entries.get(index)?.clone();
        let proof = audit_path(index, &self.leaves);
        Some(InclusionProof {
            entry,
            leaf_hash: encode_hash(self.leaves[index]),
            tree_size: self.tree_size(),
            root_hash: encode_hash(*self.roots.last()?),
            inclusion_proof: proof.iter().map(|hash| encode_hash(*hash)).collect(),
        })
    }

    pub fn consistency(
        &self,
        first_size: u64,
        second_size: u64,
    ) -> Result<ConsistencyProof, String> {
        if first_size > second_size {
            return Err("first_size must not exceed second_size".into());
        }
        if second_size > self.tree_size() {
            return Err("second_size exceeds current tree size".into());
        }

        let first = usize::try_from(first_size).map_err(|_| "first_size is too large")?;
        let second = usize::try_from(second_size).map_err(|_| "second_size is too large")?;
        let proof = if first == 0 || first == second {
            Vec::new()
        } else {
            consistency_subproof(first, &self.leaves[..second], true)
        };

        Ok(ConsistencyProof {
            first_size,
            second_size,
            first_root: encode_hash(self.roots[first]),
            second_root: encode_hash(self.roots[second]),
            proof: proof.iter().map(|hash| encode_hash(*hash)).collect(),
        })
    }

    pub fn root_at(&self, size: u64) -> Option<String> {
        let size = usize::try_from(size).ok()?;
        self.roots.get(size).map(|hash| encode_hash(*hash))
    }
}

pub fn verify_inclusion(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: &Hash,
    proof: &[Hash],
    root_hash: &Hash,
) -> bool {
    let Ok(mut leaf_index) = usize::try_from(leaf_index) else {
        return false;
    };
    let Ok(tree_size) = usize::try_from(tree_size) else {
        return false;
    };
    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }

    let mut last = tree_size - 1;
    let mut hash = *leaf_hash;

    for sibling in proof {
        if last == 0 {
            return false;
        }
        if leaf_index % 2 == 1 || leaf_index == last {
            hash = hash_nodes(sibling, &hash);
            while leaf_index % 2 == 0 && leaf_index != 0 {
                leaf_index >>= 1;
                last >>= 1;
            }
        } else {
            hash = hash_nodes(&hash, sibling);
        }
        leaf_index >>= 1;
        last >>= 1;
    }

    last == 0 && hash == *root_hash
}

pub fn verify_consistency(
    first_size: u64,
    second_size: u64,
    first_root: &Hash,
    second_root: &Hash,
    proof: &[Hash],
) -> bool {
    if first_size > second_size {
        return false;
    }
    if first_size == 0 {
        return proof.is_empty() && *first_root == empty_root();
    }
    if first_size == second_size {
        return proof.is_empty() && first_root == second_root;
    }

    let mut first_index = first_size - 1;
    let mut second_index = second_size - 1;

    while first_index % 2 == 1 {
        first_index >>= 1;
        second_index >>= 1;
    }

    let mut first_hash;
    let mut second_hash;
    let remaining = if first_index == 0 {
        first_hash = *first_root;
        second_hash = *first_root;
        proof
    } else {
        let Some(first) = proof.first() else {
            return false;
        };
        first_hash = *first;
        second_hash = *first;
        &proof[1..]
    };

    for sibling in remaining {
        if second_index == 0 {
            return false;
        }
        if first_index % 2 == 1 || first_index == second_index {
            first_hash = hash_nodes(sibling, &first_hash);
            second_hash = hash_nodes(sibling, &second_hash);
            while first_index % 2 == 0 && first_index != 0 {
                first_index >>= 1;
                second_index >>= 1;
            }
        } else {
            second_hash = hash_nodes(&second_hash, sibling);
        }
        first_index >>= 1;
        second_index >>= 1;
    }

    second_index == 0 && first_hash == *first_root && second_hash == *second_root
}

fn entry_index(entries: &[LogEntry]) -> u64 {
    entries.len() as u64 - 1
}

fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

fn hash_leaf(bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0]);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hash_nodes(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([1]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn hash_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}

fn encode_hash(hash: Hash) -> String {
    URL_SAFE_NO_PAD.encode(hash)
}

fn merkle_root(leaves: &[Hash]) -> Hash {
    match leaves {
        [] => empty_root(),
        [leaf] => *leaf,
        _ => {
            let split = largest_power_of_two_less_than(leaves.len());
            hash_nodes(
                &merkle_root(&leaves[..split]),
                &merkle_root(&leaves[split..]),
            )
        }
    }
}

fn largest_power_of_two_less_than(value: usize) -> usize {
    let mut power = 1;
    while power * 2 < value {
        power *= 2;
    }
    power
}

fn audit_path(index: usize, leaves: &[Hash]) -> Vec<Hash> {
    if leaves.len() <= 1 {
        return Vec::new();
    }

    let split = largest_power_of_two_less_than(leaves.len());
    if index < split {
        let mut path = audit_path(index, &leaves[..split]);
        path.push(merkle_root(&leaves[split..]));
        path
    } else {
        let mut path = audit_path(index - split, &leaves[split..]);
        path.push(merkle_root(&leaves[..split]));
        path
    }
}

fn consistency_subproof(first_size: usize, leaves: &[Hash], complete: bool) -> Vec<Hash> {
    if first_size == leaves.len() {
        return if complete {
            Vec::new()
        } else {
            vec![merkle_root(leaves)]
        };
    }

    let split = largest_power_of_two_less_than(leaves.len());
    if first_size <= split {
        let mut proof = consistency_subproof(first_size, &leaves[..split], complete);
        proof.push(merkle_root(&leaves[split..]));
        proof
    } else {
        let mut proof = consistency_subproof(first_size - split, &leaves[split..], false);
        proof.push(merkle_root(&leaves[..split]));
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn credential(index: u64) -> Credential {
        Credential {
            version: 1,
            issuer: "did:mesh:issuer".into(),
            subject: format!("holder-{index}"),
            claims: BTreeMap::new(),
            issued_at: 1_000 + index as i64,
            expires_at: 2_000 + index as i64,
            key_id: "key".into(),
            signature: "signature".into(),
        }
    }

    fn populated(size: u64) -> TransparencyLog {
        let mut log = TransparencyLog::new();
        for index in 0..size {
            log.append(&credential(index)).expect("append");
        }
        log
    }

    fn decode(value: &str) -> Hash {
        URL_SAFE_NO_PAD
            .decode(value)
            .expect("base64")
            .try_into()
            .expect("hash")
    }

    #[test]
    fn includes_every_leaf_at_every_size() {
        let mut log = TransparencyLog::new();
        log.append(&credential(0)).expect("append");
        assert_eq!(log.tree_size(), 1);
        assert_eq!(log.head().root_hash, log.root_at(1).expect("root"));

        for size in 1..=16 {
            if log.tree_size() < size {
                log.append(&credential(size)).expect("append");
            }
            let root = decode(&log.head().root_hash);
            for index in 0..size {
                let proof = log.inclusion(index).expect("proof");
                assert_eq!(proof.tree_size, size);
                let leaf = decode(&proof.leaf_hash);
                let siblings = proof
                    .inclusion_proof
                    .iter()
                    .map(|value| decode(value))
                    .collect::<Vec<_>>();
                assert!(
                    verify_inclusion(index, size, &leaf, &siblings, &root),
                    "inclusion failed for index {index} at size {size}"
                );

                let mut tampered = leaf;
                tampered[0] ^= 1;
                assert!(!verify_inclusion(index, size, &tampered, &siblings, &root));
            }
        }
    }

    #[test]
    fn proves_consistency_for_every_prefix() {
        let size = 16;
        let log = populated(size);
        let roots = (0..=size)
            .map(|prefix| decode(&log.root_at(prefix).expect("root")))
            .collect::<Vec<_>>();

        for second in 1..=size {
            for first in 0..=second {
                let proof = log.consistency(first, second).expect("proof");
                let siblings = proof
                    .proof
                    .iter()
                    .map(|value| decode(value))
                    .collect::<Vec<_>>();
                assert!(
                    verify_consistency(
                        first,
                        second,
                        &roots[first as usize],
                        &roots[second as usize],
                        &siblings
                    ),
                    "consistency failed for {first} -> {second}"
                );
            }
        }
    }

    #[test]
    fn rejects_tampered_consistency_proofs() {
        let log = populated(8);
        let proof = log.consistency(3, 8).expect("proof");
        let mut siblings = proof
            .proof
            .iter()
            .map(|value| decode(value))
            .collect::<Vec<_>>();
        let first = decode(&proof.first_root);
        let second = decode(&proof.second_root);

        assert!(verify_consistency(3, 8, &first, &second, &siblings));
        siblings[0][0] ^= 1;
        assert!(!verify_consistency(3, 8, &first, &second, &siblings));
        assert!(!verify_consistency(4, 8, &first, &second, &siblings));
        assert!(!verify_consistency(3, 7, &first, &second, &siblings));
    }

    #[test]
    fn root_history_is_append_only() {
        let mut log = populated(5);
        let before = log.root_at(5).expect("root");
        log.append(&credential(5)).expect("append");
        assert_eq!(log.root_at(5).as_deref(), Some(before.as_str()));
        assert_ne!(log.root_at(6), Some(before));
        assert!(log.consistency(6, 5).is_err());
        assert!(log.consistency(0, 7).is_err());
    }

    #[test]
    fn entry_commits_to_credential_and_subject_hashes() {
        let mut log = TransparencyLog::new();
        let credential = credential(1);
        let proof = log.append(&credential).expect("append");
        assert_eq!(
            proof.entry.credential_hash,
            credential.digest().expect("digest")
        );
        assert_eq!(
            proof.entry.subject_hash,
            hash_b64(credential.subject.as_bytes())
        );
        assert_eq!(proof.entry.index, 0);
        assert_eq!(log.entry(1), None);
        assert_eq!(log.inclusion(1), None);
        assert_eq!(log.head().root_hash, log.root_at(1).expect("root"));
    }

    #[test]
    fn reopens_a_persisted_log_without_changing_history() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "credential-mesh-log-{}-{unique}",
            std::process::id()
        ));
        let path = directory.join("transparency.log");

        let (root, third) = {
            let mut log = TransparencyLog::open(&path).expect("open");
            for index in 0..3 {
                log.append(&credential(index)).expect("append");
            }
            (
                log.root_at(3).expect("root"),
                log.entry(2).expect("entry").clone(),
            )
        };

        let mut reopened = TransparencyLog::open(&path).expect("reopen");
        assert_eq!(reopened.tree_size(), 3);
        assert_eq!(reopened.root_at(3).as_deref(), Some(root.as_str()));
        assert_eq!(reopened.entry(2), Some(&third));

        let proof = reopened.append(&credential(3)).expect("append");
        assert_eq!(proof.entry.index, 3);
        assert_eq!(proof.tree_size, 4);
        assert_eq!(reopened.root_at(3).as_deref(), Some(root.as_str()));

        std::fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn empty_tree_has_the_canonical_root() {
        let log = TransparencyLog::new();
        assert_eq!(log.head().tree_size, 0);
        assert_eq!(
            log.head().root_hash,
            URL_SAFE_NO_PAD.encode(Sha256::digest([]))
        );
        assert_eq!(log.consistency(0, 0).expect("proof").proof.len(), 0);
    }
}
