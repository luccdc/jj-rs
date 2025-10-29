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
    ($v:expr) => {{ $v.to_string() }};
}

#[macro_export]
macro_rules! strvec {
    ($($v:expr),+$(,)?) => {
        vec![
            $($v.to_string()),+
        ]
    }
}
