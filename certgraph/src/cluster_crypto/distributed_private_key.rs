use super::PrivateKey;
use super::Signee;
use super::locations::Locations;
use std;
use std::fmt::Display;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedPrivateKey {
    pub(crate) key: PrivateKey,
    pub(crate) locations: Locations,
    pub(crate) signees: Vec<Signee>,
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

        Ok(())
    }
}
