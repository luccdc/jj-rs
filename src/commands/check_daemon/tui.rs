use std::sync::RwLock;

use crossterm::event::{self, Event};
use ratatui::text::Text;

pub fn main(
    _checks: &RwLock<super::RuntimeDaemonConfig>,
    _daemon: &super::daemon::DaemonHandle,
    _logs: &super::logs::LogHandler,
    _prompt_reader: std::io::PipeReader,
    _answer_writer: std::io::PipeWriter,
    _scope: &std::thread::Scope<'_, '_>,
) -> anyhow::Result<()> {
    let mut terminal = ratatui::init();
    loop {
        terminal.draw(|frame| {
            let text = Text::raw("Hello world!");
            frame.render_widget(text, frame.area());
        })?;

        if matches!(event::read()?, Event::Key(_)) {
            break;
        }
    }
    ratatui::restore();
    Ok(())
}
