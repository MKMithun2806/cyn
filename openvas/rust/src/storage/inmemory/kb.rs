// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{collections::HashMap, mem::size_of, sync::RwLock};

use async_trait::async_trait;

use crate::storage::{
    Dispatcher, Remover, Retriever,
    error::StorageError,
    items::kb::{GetKbContextKey, KbContext, KbContextKey, KbItem, KbKey},
};

type Kb = HashMap<KbKey, Vec<KbItem>>;

/// Kbs are bound to a scan_id and a kb_key.
///
/// To make lookups easier KB items are fetched by a scan_id, followed by the kb key this should
/// make required_key verifications relatively simple.
type Kbs = HashMap<KbContext, Kb>;

/// Approximate size and cardinality of retained in-memory KB contents.
#[derive(Clone, Copy, Debug, Default)]
pub struct KbMemoryStats {
    pub keys: usize,
    pub items: usize,
    /// Approximate allocated bytes for value payloads and vector containers.
    /// Key allocations and HashMap bucket/control-array overhead are not included.
    pub approximate_bytes: usize,
}

#[derive(Debug, Default)]
pub struct InMemoryKbStorage(RwLock<Kbs>);

fn item_allocated_bytes(item: &KbItem) -> usize {
    match item {
        KbItem::String(value) => value.capacity(),
        KbItem::Data(value) => value.capacity(),
        KbItem::Array(values) => values
            .capacity()
            .saturating_mul(size_of::<KbItem>())
            .saturating_add(values.iter().map(item_allocated_bytes).sum::<usize>()),
        KbItem::Dict(values) => values
            .capacity()
            .saturating_mul(size_of::<(String, KbItem)>())
            .saturating_add(
                values
                    .iter()
                    .map(|(key, value)| key.capacity().saturating_add(item_allocated_bytes(value)))
                    .sum::<usize>(),
            ),
        KbItem::Number(_) | KbItem::Boolean(_) | KbItem::Null => 0,
    }
}

impl InMemoryKbStorage {
    /// Measures retained KB contents while holding a shared lock, without cloning values.
    pub fn memory_stats(&self) -> Result<KbMemoryStats, StorageError> {
        let kbs = self.0.read()?;
        let mut stats = KbMemoryStats::default();
        for kb in kbs.values() {
            for items in kb.values() {
                stats.keys = stats.keys.saturating_add(1);
                stats.items = stats.items.saturating_add(items.len());
                stats.approximate_bytes = stats
                    .approximate_bytes
                    .saturating_add(items.capacity().saturating_mul(size_of::<KbItem>()))
                    .saturating_add(items.iter().map(item_allocated_bytes).sum::<usize>());
            }
        }
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{Dispatcher, ScanID, Target};

    #[tokio::test]
    async fn memory_stats_count_appended_items_without_cloning_values() {
        let storage = InMemoryKbStorage::default();
        let key = KbContextKey(
            (ScanID("scan".into()), Target("127.0.0.1".into())),
            KbKey::Custom("test/key".into()),
        );

        storage
            .dispatch(key.clone(), KbItem::String("small".into()))
            .await
            .unwrap();
        let first = storage.memory_stats().unwrap();
        assert_eq!((first.keys, first.items), (1, 1));

        storage
            .dispatch(key, KbItem::Data(vec![0; 256]))
            .await
            .unwrap();
        let second = storage.memory_stats().unwrap();
        assert_eq!((second.keys, second.items), (1, 2));
        assert!(second.approximate_bytes >= first.approximate_bytes + 256);
    }
}

#[async_trait]
impl Dispatcher<KbContextKey> for InMemoryKbStorage {
    type Item = KbItem;
    async fn dispatch(&self, key: KbContextKey, item: KbItem) -> Result<(), StorageError> {
        let mut kbs = self.0.write()?;
        match kbs.get_mut(&key.0) {
            Some(kb) => {
                if let Some(kb) = kb.get_mut(&key.1) {
                    kb.push(item);
                } else {
                    kb.insert(key.1, vec![item]);
                }
            }
            _ => {
                let mut kb = Kb::new();
                kb.insert(key.1, vec![item]);
                kbs.insert(key.0, kb);
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Retriever<KbContextKey> for InMemoryKbStorage {
    type Item = Vec<KbItem>;
    async fn retrieve(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        let kbs = self.0.read()?;
        match kbs.get(&key.0) {
            Some(kb) => {
                if key.1.is_pattern() {
                    let mut ret = vec![];
                    for (kb_key, items) in kb {
                        if kb_key.matches(&key.1) {
                            ret.extend(items.clone());
                        }
                    }
                    Ok(Some(ret))
                } else {
                    Ok(kb.get(&key.1).cloned())
                }
            }
            _ => Ok(None),
        }
    }
}

#[async_trait]
impl Retriever<GetKbContextKey> for InMemoryKbStorage {
    type Item = Vec<(String, Vec<KbItem>)>;
    async fn retrieve(&self, key: &GetKbContextKey) -> Result<Option<Self::Item>, StorageError> {
        let kbs = self.0.read()?;
        match kbs.get(&key.0) {
            Some(kb) => {
                if key.1.is_pattern() {
                    let mut ret = vec![];
                    for (kb_key, items) in kb {
                        if kb_key.matches(&key.1) {
                            ret.push((kb_key.to_string(), items.clone()));
                        }
                    }
                    Ok(Some(ret))
                } else {
                    Ok(kb
                        .get(&key.1)
                        .map(|items| vec![(key.1.to_string(), items.clone())]))
                }
            }
            _ => Ok(None),
        }
    }
}

#[async_trait]
impl Remover<KbContextKey> for InMemoryKbStorage {
    type Item = Vec<KbItem>;
    async fn remove(&self, key: &KbContextKey) -> Result<Option<Self::Item>, StorageError> {
        let mut kbs = self.0.write().unwrap();
        match kbs.get_mut(&key.0) {
            Some(kb) => Ok(kb.remove(&key.1)),
            _ => Ok(None),
        }
    }
}
