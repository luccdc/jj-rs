#[macro_export]
macro_rules! define_commands {
    ($($cmd:ident => $($struct:ident)::+),+$(,)?) => {
        #[derive(::clap::Subcommand, Debug)]
        enum Commands {
            $($cmd($($struct)::+)),+,
        }

        impl Commands {
            fn execute(self) -> anyhow::Result<()> {
                use crate::commands::Command;

                fn _type_check<F: crate::commands::Command>(_a: &F) {}

                match self {
                    $(Self::$cmd(inner) => {
                        _type_check(&inner);
                        inner.execute()
                    }),+,
                }
            }
        }
    };
}

#[macro_export]
macro_rules! ownstr {
    ($v:expr) => {{
        $v.to_string()
    }};
}

#[macro_export]
macro_rules! strvec {
    ($($v:expr),+$(,)?) => {
        vec![
            $($v.to_string()),+
        ]
    };
}

#[macro_export]
macro_rules! flags {
    ($flags:ident) => {{
        let flags = stringify!($flags);
        let mut global = false;
        let other_flags = flags
            .chars()
            .filter_map(|c| match c {
                'g' => {
                    global = true;
                    None
                }
                'x' | 'm' | 's' => Some(c.to_string()),
                _ => None,
            })
            .collect::<String>();

        (global, other_flags)
    }};
}

#[macro_export]
macro_rules! pcre_join_fmt_string {
    ($expr:tt) => {
        "{}"
    };
    ($_tt:tt $($expr:tt)+) => {
        concat!("{}", pcre_join_fmt_string!($($expr)*))
    };
}

#[macro_export]
macro_rules! pcre_join_sections {
    ($var:ident $($tt:tt)+) => {
        format!("{}{}", $var, $crate::pcre_join_sections!($($tt)+))
    };
    ($var:tt $($tt:tt)+) => {
        format!("{}{}", $var, $crate::pcre_join_sections!($($tt)+))
    };
    ($expr:expr) => { $expr };
    ($var:tt) => { format!("{}", $var) };
}

#[macro_export]
macro_rules! pcre_regex_flags_or_replace {
    (?) => {
        (false, "", ())
    };
    (/) => {
        (false, "", ())
    };
    (? $flags:ident) => {{
        let (global, other_flags) = $crate::flags!($flags);
        (global, other_flags, ())
    }};
    (/ $flags:ident) => {{
        let (global, other_flags) = $crate::flags!($flags);
        (global, other_flags, ())
    }};

    (/ $replace:tt / $flags:ident) => {{
        let (global, other_flags) = $crate::flags!($flags);
        (global, other_flags, $replace)
    }};

    (/ $replace:tt /) => {{
        (false, "", $replace)
    }};

    (? { $($replace:tt)* } $flags:ident) => {{
        let (global, other_flags) = flags!($flags);
        (global, other_flags, $crate::pcre_join_sections!($($replace)*))
    }};

    (? { $($replace:tt)* }) => {{
        (false, "", $crate::pcre_join_sections!($($replace)*))
    }};
}

#[macro_export]
macro_rules! pcre_regex {
    ({ $($regex:tt)* } $($tt:tt)*) => {{
        let (global, other_flags, replace) = $crate::pcre_regex_flags_or_replace!(? $($tt)*);
        (global, other_flags, $crate::pcre_join_sections!($($regex)*), replace)
    }};

    (/$regex:tt/ $($tt:tt)*) => {{
        let (global, other_flags, replace) = $crate::pcre_regex_flags_or_replace!(/ $($tt)*);
        (global, other_flags, $crate::pcre_join_sections!($regex), replace)
    }};
}

/// This implementation is built out of a contest of which is better for the task, Perl or Rust?
///
/// This macro allows for using the following syntaxes:
///
/// ```
/// use jj_rs::pcre;
///
/// let asdf = "asdf";
///
/// // Basic assertion; does it match?
/// assert!( pcre!("asdf" =~ qr/"as"/xms));
/// assert!(!pcre!("asdf" =~ qr/"fs"/xms));
/// assert!( pcre!( asdf  =~ qr/"as"/xms));
///
/// // Basic replacement
/// assert_eq!(pcre!(asdf =~ s/"as"/"sa"/xms), "sadf");
/// assert_eq!(pcre!(asdf =~ s/"as"/"sa"/xms), "sadf");
///
/// // Global vs non global replacement
/// assert_eq!(pcre!("asdfasdf" =~ s/"as"/"sa"/xms), "sadfasdf");
/// assert_eq!(pcre!("asdfasdf" =~ s/"as"/"sa"/xgms), "sadfsadf");
///
/// // Multi line regex for clarity
/// assert!(pcre!{
///     "127.0.0.1" =~ qr{
///         r"([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
///         r"([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
///         r"([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])\."
///         r"([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
///     }xms
/// });
/// ```
///
/// It does function a little differently in that:
/// 1. Parts of the regular expression have to be in quotes
/// 2. If the variable the regular expression is operating on is not an identifier, it has to be wrapped in quotes
/// 3. If using xms, all have to be used in that order
#[macro_export]
macro_rules! pcre {
    (($inp:expr) =~ s $($tt:tt)*) => {{
        let (global, other_flags, regex, replace_with) = $crate::pcre_regex!($($tt)*);
        let re = ::regex::Regex::new(&format!("(?{other_flags}){}", &regex))
            .expect(&format!("Regex provided is invalid: {}", &regex));

        if global {
            re.replace_all($inp, replace_with)
        } else {
            re.replace($inp, replace_with)
        }
    }};

    (($inp:expr) =~ m $($tt:tt)*) => {{
        let (global, other_flags, regex, _) = $crate::pcre_regex!($($tt)*);
        let re = ::regex::Regex::new(&format!("(?{other_flags}){}", &regex))
            .expect(&format!("Regex provided is invalid: {}", &regex));

        if global {
            re.captures_iter($inp)
        } else {
            re.captures($inp)
        }
    }};

    (($inp:expr) =~ qr $($tt:tt)*) => {{
        let (_, other_flags, regex, _) = $crate::pcre_regex!($($tt)*);
        let re = ::regex::Regex::new(&format!("(?{other_flags}){}", regex))
            .expect(&format!("Regex provided is invalid: {}", &regex));

        re.is_match($inp)
    }};

    ($inp:tt $($tt:tt)*) => {{
        $crate::pcre!(($inp) $($tt)*)
    }};
}
