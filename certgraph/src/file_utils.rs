use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

pub(crate) fn globvec(location: &Path, globstr: &str) -> Vec<PathBuf> {
    let mut globoptions = glob::MatchOptions::new();
    globoptions.require_literal_leading_dot = true;

    glob::glob_with(location.join(globstr).to_str().unwrap(), globoptions)
        .unwrap()
        .map(|x| x.unwrap())
        .filter(|x| !x.is_symlink())
        .collect::<Vec<_>>()
}

pub(crate) async fn read_file_to_string(file_path: PathBuf) -> String {
    let mut file = tokio::fs::File::open(file_path.clone())
        .await
        .expect(format!("failed to open file {:?}", file_path).as_str());
    let mut contents = String::new();
    file.read_to_string(&mut contents).await.expect("failed to read file");
    contents
}
