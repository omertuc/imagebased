use std::{
    collections::HashSet,
    fmt::{Debug, Display},
};

use serde_json::Value;

use crate::json_tools;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locations(pub(crate) HashSet<Location>);

impl AsRef<HashSet<Location>> for Locations {
    fn as_ref(&self) -> &HashSet<Location> {
        &self.0
    }
}

impl AsMut<HashSet<Location>> for Locations {
    fn as_mut(&mut self) -> &mut HashSet<Location> {
        &mut self.0
    }
}

impl Display for Locations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let locations = self.0.iter().collect::<Vec<_>>();
        write!(f, "[")?;
        for location in locations {
            write!(f, "{}, ", location)?;
        }
        write!(f, "]")
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) enum Location {
    K8s(K8sLocation),
    Filesystem(FileLocation),
}

impl Location {
    pub fn k8s(
        k8s_resource_location: K8sResourceLocation,
        prefix: &str,
        key: &str,
        base64_encoded: bool,
    ) -> Location {
        Location::K8s(K8sLocation {
            resource_location: k8s_resource_location.clone(),
            yaml_location: YamlLocation {
                json_pointer: format!("{}/{}", prefix, key.to_string().replace("/", "~1")),
                value: LocationValueType::Unknown,
                base64_encoded,
            },
        })
    }

    pub fn file_yaml(file_path: &str, prefix: &str, key: &str, base64_encoded: bool) -> Location {
        Location::Filesystem(FileLocation {
            file_path: file_path.to_string(),
            content_location: FileContentLocation::Yaml(YamlLocation {
                json_pointer: format!("{}/{}", prefix, key.to_string().replace("/", "~1")),
                value: LocationValueType::Unknown,
                base64_encoded,
            }),
        })
    }
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
                FileContentLocation::Yaml(yaml_location) => {
                    let mut new_yaml_location = yaml_location.clone();
                    new_yaml_location.value =
                        LocationValueType::Pem(PemLocationInfo::new(pem_bundle_index));
                    let mut new_file_location = file_location.clone();
                    new_file_location.content_location =
                        FileContentLocation::Yaml(new_yaml_location);
                    Self::Filesystem(new_file_location)
                }
            },
        }
    }

    pub(crate) fn with_jwt(&self) -> Self {
        match self {
            Self::K8s(k8s_location) => {
                let mut new_k8s_location = k8s_location.clone();
                new_k8s_location.yaml_location.value = LocationValueType::Jwt;
                Self::K8s(new_k8s_location)
            }
            Self::Filesystem(file_location) => match &file_location.content_location {
                FileContentLocation::Raw(location_value_type) => match location_value_type {
                    LocationValueType::Pem(_) => panic!("Already has PEM info"),
                    LocationValueType::Jwt => panic!("Already has JWT info"),
                    LocationValueType::Unknown => {
                        let mut new_file_location = file_location.clone();
                        new_file_location.content_location =
                            FileContentLocation::Raw(LocationValueType::Jwt);
                        Self::Filesystem(new_file_location)
                    }
                },
                FileContentLocation::Yaml(yaml_location) => {
                    let mut new_yaml_location = yaml_location.clone();
                    new_yaml_location.value = LocationValueType::Jwt;
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
    Yaml(YamlLocation),
}

impl std::fmt::Display for FileContentLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileContentLocation::Raw(pem_location_info) => write!(f, "{}", pem_location_info),
            FileContentLocation::Yaml(yaml_location) => write!(f, "{}", yaml_location),
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
    pub(crate) base64_encoded: bool,
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
