use super::{
    crypto_utils::generate_rsa_key, distributed_public_key::DistributedPublicKey, locations::Locations, PrivateKey, PublicKey, Signee,
};
use std::{self, cell::RefCell, fmt::Display, rc::Rc};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedPrivateKey {
    pub(crate) key: PrivateKey,
    pub(crate) locations: Locations,
    pub(crate) signees: Vec<Signee>,
    pub(crate) associated_distributed_public_key: Option<Rc<RefCell<DistributedPublicKey>>>,
}

impl Display for DistributedPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Standalone priv {:03} locations {}",
            self.locations.0.len(),
            self.locations,
            // "<>",
        )?;

        if self.signees.len() > 0 {
            writeln!(f, "")?;
        }

        for signee in &self.signees {
            writeln!(f, "- {}", signee)?;
        }

        if let Some(public_key) = &self.associated_distributed_public_key {
            writeln!(f, "* Associated public key at {}", (*public_key).borrow())?;
        }

        Ok(())
    }
}

impl DistributedPrivateKey {
    pub(crate) fn regenerate(&mut self) {
        let mut rng = rand::thread_rng();
        let (self_new_rsa_private_key, self_new_key_pair) = generate_rsa_key(&mut rng);

        for signee in &mut self.signees {
            signee.regenerate(&PublicKey::from(&self.key), Some(&self_new_key_pair));
        }

        self.key = PrivateKey::Rsa(self_new_rsa_private_key);
    }
}

