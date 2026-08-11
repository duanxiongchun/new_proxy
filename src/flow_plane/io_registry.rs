use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IoOwnerKey {
    pub ifindex: u32,
    pub queue_id: u32,
}

impl IoOwnerKey {
    pub const fn new(ifindex: u32, queue_id: u32) -> Self {
        Self { ifindex, queue_id }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RegistryError {
    #[error("an IO owner is already registered for {0:?}")]
    DuplicateOwner(IoOwnerKey),
}

#[derive(Debug)]
pub struct IoRegistry<T> {
    owners: HashMap<IoOwnerKey, T>,
}

impl<T> IoRegistry<T> {
    pub fn new() -> Self {
        Self {
            owners: HashMap::new(),
        }
    }

    pub fn register(&mut self, key: IoOwnerKey, owner: T) -> Result<(), RegistryError> {
        if self.owners.contains_key(&key) {
            return Err(RegistryError::DuplicateOwner(key));
        }
        self.owners.insert(key, owner);
        Ok(())
    }

    pub fn get(&self, key: IoOwnerKey) -> Option<&T> {
        self.owners.get(&key)
    }

    pub fn contains(&self, key: IoOwnerKey) -> bool {
        self.owners.contains_key(&key)
    }

    pub fn len(&self) -> usize {
        self.owners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&IoOwnerKey, &T)> {
        self.owners.iter()
    }
}

impl<T> Default for IoRegistry<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_unit_io_registry_keys_by_ifindex_and_queue() {
        let mut registry = IoRegistry::new();
        registry
            .register(IoOwnerKey::new(2, 0), "intercept")
            .unwrap();
        registry.register(IoOwnerKey::new(3, 0), "tunnel").unwrap();

        assert_eq!(registry.get(IoOwnerKey::new(2, 0)), Some(&"intercept"));
        assert_eq!(registry.get(IoOwnerKey::new(3, 0)), Some(&"tunnel"));
    }

    #[test]
    fn v1_unit_io_registry_rejects_duplicate_owner() {
        let mut registry = IoRegistry::new();
        registry.register(IoOwnerKey::new(2, 0), "first").unwrap();

        assert_eq!(
            registry.register(IoOwnerKey::new(2, 0), "second"),
            Err(RegistryError::DuplicateOwner(IoOwnerKey::new(2, 0)))
        );
    }
}
