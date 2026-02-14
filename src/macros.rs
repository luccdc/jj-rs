/// One time macro used to define the commands that are used for the main
/// clap argument parser
#[macro_export]
macro_rules! define_commands {
    ($mname:ident::$cname:ident { $($(#[$($attr:tt)*])* $([$($cfg:tt),+$(,)?])? $cmd:ident$(, $alias:ident)? => $mod:ident::$struct:ident),+$(,)? }) => {
        mod $mname {
            $(
                $($(
                    #[cfg($cfg)]
                )*)?
                mod $mod;
            )+

            #[derive(::clap::Subcommand, Debug)]
            pub enum $cname {
                $(
                    $(#[$($attr)*])*
                    $($(
                        #[cfg($cfg)]
                    )*)?
                    $(#[command(visible_alias(stringify!($alias)))])?
                    $cmd($mod::$struct)
                ),+,
            }

            impl $cname {
                pub fn execute(self) -> eyre::Result<()> {
                    use $crate::commands::Command;

                    fn _type_check<F: $crate::commands::Command>(_a: &F) {}

                    match self {
                        $(
                            $(#[$($attr)*])*
                            $($(
                                #[cfg($cfg)]
                            )*)?
                            Self::$cmd(inner) => {
                                _type_check(&inner);
                                inner.execute()
                            }
                        ),+,
                    }
                }

                pub fn setup_tracing(&self) -> eyre::Result<()> {
                    match self {
                        $(
                            $(#[$($attr)*])*
                            $($(
                                #[cfg($cfg)]
                            )*)?
                            Self::$cmd(inner) => {
                                inner.setup_tracing()
                            }
                        ),+,
                    }
                }
            }

            pub trait Command: clap::Parser {
                fn execute(self) -> eyre::Result<()>;

                fn setup_tracing(&self) -> eyre::Result<()> {
                    use ::tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

                    ::tracing_subscriber::registry()
                        .with(::tracing_subscriber::fmt::layer())
                        .with(
                            ::tracing_subscriber::filter::Targets::new()
                                .with_target("jj_rs", ::tracing::Level::INFO),
                        )
                        .init();

                    Ok(())
                }
            }
        }
    };
}

/// One time macro used to define the list of checks the system is aware of
#[macro_export]
macro_rules! define_checks {
    ($mname:ident::$cname:ident { $($(#[$($attr:tt)*])* $name:ident$(, $alias:expr)? => $mod:ident::$struct:ident),+$(,)? }) => {
        mod $mname {
            $(
                pub mod $mod;
            )+

            pub use $crate::utils::checks::*;

            #[derive(::clap::Subcommand, ::serde::Serialize, ::serde::Deserialize, Debug, Clone)]
            pub enum $cname {
                $(
                    $(#[$($attr)*])*
                    $(#[serde(rename = $alias)])?
                    $name($mod::$struct)
                ),+,
            }

            impl $cname {
                pub fn check_names() -> Vec<&'static str> {
                    vec![
                        $(
                            $mod::$struct::display_name(&$mod::$struct::default())
                        ),+,
                    ]
                }

                pub fn display_name(&self) -> &'static str {
                    match self {
                        $(
                            Self::$name(inner) => inner.display_name()
                        ),+,
                    }
                }

                pub fn troubleshooter(self) -> Box<dyn $crate::utils::checks::Troubleshooter> {
                    match self {
                        $(
                            Self::$name(inner) => Box::new(inner)
                        ),+,
                    }
                }
            }
        }
    };
}

/// Macro that performs very similarly to vec![], except it calls
/// .`to_string()` on all items provided to it
///
/// Normal use of vec![] can be confusing with String vecs:
/// ```compile_fail
/// let string_vec: Vec<String> = vec!["1", "2"];
/// ```
///
/// Or, it can be verbose:
/// ```
/// let string_vec: Vec<String> = vec!["1".to_string(), "2".to_string()];
/// ```
///
/// This macro makes creating such vecs easier:
/// ```
/// # use jj_rs::strvec;
/// let string_vec: Vec<String> = strvec!["1", "2"];
/// ```
#[macro_export]
macro_rules! strvec {
    ($($v:expr),+$(,)?) => {
        vec![
            $($v.to_string()),+
        ]
    };
}

#[doc(hidden)]
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
#[doc(hidden)]
macro_rules! pcre_join_fmt_string {
    ($expr:tt) => {
        "{}"
    };
    ($_tt:tt $($expr:tt)+) => {
        concat!("{}", pcre_join_fmt_string!($($expr)*))
    };
}

#[macro_export]
#[doc(hidden)]
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
#[doc(hidden)]
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
#[doc(hidden)]
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

#[macro_export]
#[doc(hidden)]
macro_rules! pcre_format_regex {
    ($($tt:tt)*) => {{
        let (global, other_flags, regex, replace_with) = $crate::pcre_regex!($($tt)*);
        (
            global,
            if other_flags.is_empty() {
                ::regex::Regex::new(&regex)
            } else {
                ::regex::Regex::new(&format!("(?{other_flags}){}", &regex))
            }.expect(&format!("Regex provided is invalid: {}", &regex)),
            replace_with
        )
    }};
}

/// This implementation is built out of a contest of which is better for the task, Perl or Rust?
///
/// This macro allows for using the following syntaxes:
///
/// ```
/// # use jj_rs::pcre;
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
/// By adding `dbg; ` to the start of the macro invocation, you can see debug information including
/// the resulting regular expression and all the results of using the regular expression
#[macro_export]
macro_rules! pcre {
    (dbg; ($inp:expr) =~ s $($tt:tt)*) => {{
        let (global, re, replace_with) = $crate::pcre_format_regex!($($tt)*);

        dbg!(&re);
        if global {
            dbg!(re.replace_all($inp, replace_with))
        } else {
            dbg!(re.replace($inp, replace_with))
        }
    }};

    (dbg; ($inp:expr) =~ m $($tt:tt)*) => {{
        let (_, re, _) = $crate::pcre_format_regex!($($tt)*);
        dbg!(&re);
        dbg!(re.captures_iter($inp).collect::<Vec<_>>())
    }};

    (dbg; ($inp:expr) =~ qr $($tt:tt)*) => {{
        let (_, re, _) = $crate::pcre_format_regex!($($tt)*);
        dbg!(&re);
        dbg!(re.is_match($inp))
    }};

    (dbg; & $inp:tt $($tt:tt)*) => {{
        $crate::pcre!(dbg; (&$inp) $($tt)*)
    }};

    (($inp:expr) =~ s $($tt:tt)*) => {{
        let (global, re, replace_with) = $crate::pcre_format_regex!($($tt)*);

        if global {
            re.replace_all($inp, replace_with).to_string()
        } else {
            re.replace($inp, replace_with).to_string()
        }
    }};

    (($inp:expr) =~ m $($tt:tt)*) => {{
        let (global, re, _) = $crate::pcre_format_regex!($($tt)*);

        if global {
            re.captures_iter($inp).collect::<Vec<_>>()
        } else {
            re.captures_iter($inp).take(1).collect()
        }
    }};

    (($inp:expr) =~ qr $($tt:tt)*) => {{
        let (_, re, _) = $crate::pcre_format_regex!($($tt)*);
        re.is_match($inp)
    }};

    (& $inp:tt $($tt:tt)*) => {{
        $crate::pcre!((&$inp) $($tt)*)
    }};

    ($inp:tt $($tt:tt)*) => {{
        $crate::pcre!(($inp) $($tt)*)
    }};
}

/// Spawn a tokio runtime on the current thread and run the provided Future to completion
///
/// # Example
///
/// ```
/// # use jj_rs::spawn_rt;
/// # fn demo() -> eyre::Result<()> {
/// spawn_rt!(async {
///     tokio::fs::read("/dev/zero").await
/// })?
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! spawn_rt {
    (async $($b:tt)+) => {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async $($b)+)
    }
}
