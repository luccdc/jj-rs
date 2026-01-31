/// Cut `s` down to `max_len`
pub fn truncate(max_len: usize, s: &str) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }

    s[..max_len].to_string()
}

/// Cut `s` down to `max_len` and add an ellipses if it has been shortened.
/// Returns a new string.
pub fn ellipsize(max_len: usize, s: &str) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }

    let mut result = String::with_capacity(max_len);
    // Use saturating_sub to avoid panic if max_len < 3
    let end = max_len.saturating_sub(3);
    result.push_str(&s[..end]);
    result.push_str("...");
    result
}
