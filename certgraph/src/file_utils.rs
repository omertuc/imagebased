use std::path::PathBuf;

use std::path::Path;

pub(crate) fn globvec(location: &Path, globstr: &str) -> Vec<PathBuf> {
    let mut globoptions = glob::MatchOptions::new();
    globoptions.require_literal_leading_dot = true;

    glob::glob_with(location.join(globstr).to_str().unwrap(), globoptions)
        .unwrap()
        .map(|x| x.unwrap())
        .filter(|x| !x.is_symlink())
        .collect::<Vec<_>>()
}
