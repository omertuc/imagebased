use serde_json::Value;

pub(crate) fn read_string_field(value: &Value, field: &str) -> String {
    value.as_object().unwrap().get(field).unwrap().as_str().unwrap().to_string()
}

pub(crate) fn read_metadata_string_field(value: &Value, field: &str) -> String {
    read_string_field(value.as_object().unwrap().get("metadata").unwrap(), field)
}
