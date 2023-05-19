use std::fmt::Debug;

use serde_json::Value;

use crate::json_tools;

#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) enum Location {
    K8s(K8sLocation),
    Filesystem(FileLocation),
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Location::K8s(k8s_location) => write!(
                f,
                "k8s:{}:{}",
                k8s_location.resource_location, k8s_location.yaml_location
            ),
            Location::Filesystem(file_location) => write!(
                f,
                "file:{}:{}",
                file_location.file_path, file_location.content_location
            ),
        }
    }
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
                new_k8s_location.yaml_location.value =
                    LocationValueType::Pem(PemLocationInfo { pem_bundle_index });
                Self::K8s(new_k8s_location)
            }
            Self::Filesystem(file_location) => match &file_location.content_location {
                FileContentLocation::Raw(location_value_type) => match location_value_type {
                    LocationValueType::Pem(_) => panic!("Already has PEM info"),
                    LocationValueType::Jwt => panic!("Already has JWT info"),
                    LocationValueType::Unknown => {
                        let mut new_file_location = file_location.clone();
                        new_file_location.content_location = FileContentLocation::Raw(
                            LocationValueType::Pem(PemLocationInfo::new(pem_bundle_index)),
                        );
                        Self::Filesystem(new_file_location)
                    }
                },
            },
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct PemLocationInfo {
    pub(crate) pem_bundle_index: u64,
}

impl PemLocationInfo {
    fn new(pem_bundle_index: u64) -> Self {
        Self { pem_bundle_index }
    }
}

impl std::fmt::Display for PemLocationInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, ":pem{}", self.pem_bundle_index)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct FileLocation {
    pub(crate) file_path: String,
    pub(crate) content_location: FileContentLocation,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum FileContentLocation {
    Raw(LocationValueType),
}

impl std::fmt::Display for FileContentLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileContentLocation::Raw(pem_location_info) => write!(f, "{}", pem_location_info),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum LocationValueType {
    Pem(PemLocationInfo),
    Jwt,
    Unknown,
}

impl std::fmt::Display for LocationValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocationValueType::Pem(pem_location_info) => write!(f, "{}", pem_location_info),
            LocationValueType::Jwt => write!(f, ":jwt"),
            LocationValueType::Unknown => panic!("Cannot display unknown location value type"),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct YamlLocation {
    pub(crate) json_pointer: String,
    pub(crate) value: LocationValueType,
}

impl std::fmt::Display for YamlLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, ":{}{}", self.json_pointer, self.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct K8sResourceLocation {
    pub(crate) namespace: String,
    pub(crate) kind: String,
    pub(crate) name: String,
}

impl From<&Value> for K8sResourceLocation {
    fn from(value: &Value) -> Self {
        Self {
            namespace: json_tools::read_metadata_string_field(value, "namespace"),
            kind: json_tools::read_string_field(value, "kind"),
            name: json_tools::read_metadata_string_field(value, "name"),
        }
    }
}

impl std::hash::Hash for K8sResourceLocation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.namespace.hash(state);
        self.kind.hash(state);
        self.name.hash(state);
    }
}

impl std::fmt::Display for K8sResourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}:{}", self.kind, self.namespace, self.name)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct K8sLocation {
    pub(crate) resource_location: K8sResourceLocation,
    pub(crate) yaml_location: YamlLocation,
}

impl K8sLocation {
    pub(crate) fn as_etcd_key(&self) -> String {
        format!(
            "/kubernetes.io/{}s/{}/{}",
            self.resource_location.kind.to_lowercase(),
            self.resource_location.namespace,
            self.resource_location.name,
        )
    }
}

impl std::fmt::Display for K8sLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}:{}",
            self.resource_location, self.yaml_location.json_pointer, self.yaml_location.value
        )
    }
}
