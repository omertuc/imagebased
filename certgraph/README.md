This is a tool to strip must-gathers from boring data like UUIDs,
managedFields, pod / replicaset randomized suffixes, etc. for the purpose of
easily diffing the must-gathers from 2 clusters.

# Requirements

* Rust https://rustup.rs/
* must-gathers placed in the gathers directory
* Recommended: meld

# Example usage

1. Place a must-gather called `first` inside the `gathers` directory
2. Place a must-gather called `second` inside the `gathers` directory
3. Run `cargo run --release`
4. Run `meld normalized/first normalized/second`
