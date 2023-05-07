use std::fmt::Debug;

#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) enum Location {
    K8s(K8sLocation),
    Filesystem(FileLocation),
}

impl Debug for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::K8s(arg0) => f.debug_tuple("K8s").field(arg0).finish(),
            Self::Filesystem(arg0) => f.debug_tuple("Filesystem").field(arg0).finish(),
        }
    }
}

impl Location {
    pub(crate) fn with_pem_bundle_index(&self, pem_bundle_index: u64) -> Self {
        match self {
            Self::K8s(k8s_location) => {
                let mut new_k8s_location = k8s_location.clone();
                new_k8s_location.yaml_location.pem_location.pem_bundle_index =
                    Some(pem_bundle_index);
                Self::K8s(new_k8s_location)
            }
            Self::Filesystem(file_location) => match &file_location.content_location {
                FileContentLocation::Raw(pem_location_info) => {
                    let mut new_pem_location_info = pem_location_info.clone();
                    new_pem_location_info.pem_bundle_index = Some(pem_bundle_index);
                    let mut new_file_location = file_location.clone();
                    new_file_location.content_location =
                        FileContentLocation::Raw(new_pem_location_info);
                    Self::Filesystem(new_file_location)
                }
                FileContentLocation::Yaml(yaml_location) => {
                    let mut new_yaml_location = yaml_location.clone();
                    new_yaml_location.pem_location.pem_bundle_index = Some(pem_bundle_index);
                    let mut new_file_location = file_location.clone();
                    new_file_location.content_location =
                        FileContentLocation::Yaml(new_yaml_location);
                    Self::Filesystem(new_file_location)
                }
            },
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct PemLocationInfo {
    pub(crate) pem_bundle_index: Option<u64>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct FileLocation {
    pub(crate) file_path: String,
    pub(crate) content_location: FileContentLocation,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum FileContentLocation {
    Raw(PemLocationInfo),
    Yaml(YamlLocation),
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct YamlLocation {
    pub(crate) json_path: String,
    pub(crate) pem_location: PemLocationInfo,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct K8sResourceLocation {
    pub(crate) namespace: String,
    pub(crate) kind: String,
    pub(crate) name: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct K8sLocation {
    pub(crate) resource_location: K8sResourceLocation,
    pub(crate) yaml_location: YamlLocation,
}
