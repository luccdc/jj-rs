
/// Cut s down to max_len
pub fn truncate(max_len: usize, s: String) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    
    let mut result = String::with_capacity(max_len);
    result.push_str(&s[..max_len]);
    result
}

/// Cut s down to max_len and add an ellipses if it has been shortened.
/// Returns a new string.
pub fn ellipsize(max_len: usize, s: String) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    
    let mut result = String::with_capacity(max_len);
    result.push_str(&s[..max_len-3]);
    result.push_str("...");
    result
}
