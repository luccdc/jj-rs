//! Useful Regex constants for use with `pcre!`

pub const DEC: &str = "[0-9]+";
pub const HEX: &str = "[0-9A-F]+";
pub const HEX4: &str = "[0-9A-F]{4}";
pub const HEX8: &str = "[0-9A-F]{8}";
pub const HEX2: &str = "[0-9A-F]{2}";

pub const CDEC: &str = "([0-9]+)";
pub const CHEX: &str = "([0-9A-F]+)";
pub const CHEX4: &str = "([0-9A-F]{4})";
pub const CHEX8: &str = "([0-9A-F]{8})";
pub const CHEX2: &str = "([0-9A-F]{2})";
