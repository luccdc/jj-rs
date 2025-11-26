// use std::sync::RwLock;
//
// use crossterm::event::{self, Event};
// use ratatui::text::Text;
// use tokio::net::unix::pipe::{Receiver, Sender};

// pub fn main(
//     _checks: &RwLock<super::RuntimeDaemonConfig>,
//     _daemon: &super::mux::DaemonHandle,
//     _logs: &super::logs::LogConfig,
//     _prompt_reader: Receiver,
//     _answer_writer: Sender,
//     _scope: &std::thread::Scope<'_, '_>,
// ) -> eyre::Result<()> {
//     let mut terminal = ratatui::init();
//     loop {
//         terminal.draw(|frame| {
//             let text = Text::raw("Hello world!");
//             frame.render_widget(text, frame.area());
//         })?;
//
//         if matches!(event::read()?, Event::Key(_)) {
//             break;
//         }
//     }
//     ratatui::restore();
//     Ok(())
// }
