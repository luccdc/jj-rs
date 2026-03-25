use std::{
    io::{IsTerminal, Write},
    ops::Deref,
};

pub trait PagerOutput: Write {
    fn is_terminal(&self) -> bool;
}

impl PagerOutput for std::io::Stdout {
    fn is_terminal(&self) -> bool {
        <Self as IsTerminal>::is_terminal(self)
    }
}

impl PagerOutput for Box<dyn PagerOutput> {
    fn is_terminal(&self) -> bool {
        self.deref().is_terminal()
    }
}

pub fn get_pager_output(_no_pager: bool) -> impl PagerOutput {
    std::io::stdout()
}
