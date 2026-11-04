use super::*;

/// The bare `tools:` section, as bytes (what the tests state a section as): read as `validate`,
/// `open` and `refresh` read it ([`read_tools_value`]). An empty blob is the empty section.
///
/// # Errors
///
/// The first rule the section breaks, in the grammar's words.
pub fn read_tools_section(settings: &[u8]) -> Result<ToolsCfg, String> {
    if settings.is_empty() {
        return Ok(ToolsCfg::default());
    }
    read_tools_value(serde_json::from_slice(settings).map_err(|e| e.to_string())?)
}
