use std::fmt::Display;

use super::locations::Locations;

use super::PublicKey;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistributedPublicKey {
    pub(crate) public_key: PublicKey,
    pub(crate) locations: Locations,
}

impl Display for DistributedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Standalone pub {:03} locations {}",
            self.locations.0.len(),
            self.locations,
            // "<>",
        )?;

        Ok(())
    }
}
