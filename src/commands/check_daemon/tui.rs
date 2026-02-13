//! TUI to manage the check daemon
//!
//! All major work is done on other threads/in other processes, so we can reuse
//! the render thread for pretty much everything
//!
//! To do so in a way that plays well with lifetimes, everything is async and
//! performs tasks in the main loop with tokio::select!.

#[cfg(unix)]
use std::io::PipeWriter;
use std::{
    collections::{HashMap, VecDeque},
    ops::ControlFlow,
    path::{Path, PathBuf},
    sync::RwLock,
};

use chrono::Utc;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    prelude::Margin,
    style::{Color, Style},
    text::{Line, Text},
    widgets::{Block, Clear, Tabs},
};
use strum::FromRepr;
use tokio::sync::{broadcast, mpsc};

use super::{
    CheckId, RuntimeDaemonConfig, TroubleshooterResult, check_thread::OutboundMessage, logs,
};

mod checks;
mod components {
    pub mod text_input;
}

use components::text_input::{TextInput, TextInputState};

pub async fn main<'scope, 'env: 'scope>(
    log_file_path: Option<PathBuf>,
    checks: &'env RwLock<RuntimeDaemonConfig>,
    (mut logs_reader, mut prompt_reader): (
        mpsc::Receiver<logs::LogEvent>,
        mpsc::Receiver<(CheckId, String)>,
    ),
    #[cfg(unix)] log_writer: PipeWriter,
    #[cfg(windows)] log_writer: tokio::sync::mpsc::Sender<super::logs::LogEvent>,
    (prompt_writer, checks_scope): (
        mpsc::Sender<(CheckId, String)>,
        &'scope std::thread::Scope<'scope, 'env>,
    ),
    send_shutdown: broadcast::Sender<()>,
) -> eyre::Result<()> {
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let mut terminal = ratatui::init();
    let mut reader = crossterm::event::EventStream::new();

    terminal.draw(|frame| {
        frame.render_widget(Text::raw("Loading previous logs..."), frame.area());
    })?;

    let logs = if let Some(log_file) = log_file_path {
        load_previous_logs(&log_file).await.unwrap_or_default()
    } else {
        Default::default()
    };

    let mut tui_state = Tui {
        checks,
        current_prompts: Default::default(),
        current_tab: Tab::Checks,
        current_selection: CurrentSelection::Tabs,
        logs,
        prompt_entry: Default::default(),
        check_tab_data: Default::default(),
        previous_render_time: 0,
        buffer: String::new(),
    };

    loop {
        let start = Utc::now();
        terminal.draw(|frame| render(&mut tui_state, frame))?;
        let end = Utc::now();
        tui_state.previous_render_time = ((end - start).as_seconds_f64() * 1_000.0) as usize;

        tokio::select! {
            Some(Ok(event)) = reader.next() => {
                if let ControlFlow::Break(_) = handle_key_event(
                    &mut tui_state,
                    event,
                    &log_writer,
                    &prompt_writer,
                    &checks_scope
                ).await? {
                    break;
                }
            }
            Some((check_id, prompt)) = prompt_reader.recv() => {
                tui_state.current_prompts.push_back((check_id, prompt));
                if tui_state.prompt_entry.is_none() {
                    tui_state.prompt_entry = Some(Default::default());
                }
            }
            Some(event) = logs_reader.recv() => {
                // Update events are implicitly handled
                let logs::LogEvent::Result(res) = event else { continue; };

                let check_logs = tui_state.logs.entry(res.check_id.clone()).or_default();
                check_logs.push(res);
            }
            _ = &mut ctrl_c => {
                break;
            }
            else => {
                break;
            }
        }
    }

    send_shutdown.send(())?;

    ratatui::restore();

    println!("Shutting down...");

    Ok(())
}

async fn load_previous_logs(
    path: &Path,
) -> eyre::Result<HashMap<CheckId, Vec<TroubleshooterResult>>> {
    let content = String::from_utf8(tokio::fs::read(path).await?)?;
    let entries: Vec<super::TroubleshooterResult> =
        content.split('\n').flat_map(serde_json::from_str).collect();

    let mut logs = HashMap::<_, Vec<_>>::new();

    for entry in entries {
        let log_entry = logs.entry(entry.check_id.clone());
        log_entry.or_default().push(entry);
    }

    Ok(logs)
}

fn render(tui: &mut Tui<'_>, frame: &mut Frame) {
    frame.render_widget(Clear, frame.area());

    let vertical = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(7),
        Constraint::Length(1),
    ]);
    let [tab_header, tab_body, cmdline] = vertical.areas(frame.area());

    let highlighted_style = Style::new().fg(Color::Yellow);

    let highlighted_tab_style = if tui.current_selection == CurrentSelection::Tabs {
        Style::new().bg(Color::Yellow)
    } else {
        Style::new().fg(Color::Yellow)
    };

    frame.render_widget(
        &Tabs::new(vec!["Checks", "Add", "Settings", "Logs", "Exit"])
            .highlight_style(highlighted_tab_style)
            .select(tui.current_tab as usize),
        tab_header,
    );

    let body_block = if tui.current_selection == CurrentSelection::TabBody
        && match tui.current_tab {
            Tab::Checks => checks::show_border_on_area(tui),
            _ => true,
        } {
        Block::bordered().border_style(highlighted_style)
    } else {
        Block::bordered()
    };

    let inner_area = body_block.inner(tab_body);

    frame.render_widget(body_block, tab_body);
    frame.render_widget(Clear, inner_area);
    frame.render_widget(Line::from(tui.buffer.clone()), cmdline);

    match tui.current_tab {
        Tab::Checks => checks::render(
            tui,
            frame,
            inner_area.clone(),
            tui.current_selection == CurrentSelection::TabBody,
        ),
        Tab::AddCheck => {}
        Tab::Settings => {}
        Tab::Logs => {}
        Tab::Exit => {}
    }

    if let (Some(prompt_state), Some(prompt)) = (&mut tui.prompt_entry, tui.current_prompts.get(0))
    {
        let vertical = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(3),
            Constraint::Fill(1),
        ]);
        let [_, tab_body, _] = vertical.areas(inner_area.clone());

        let input = TextInput::default().label(Some(&format!(
            "[{}.{}]: {}",
            prompt.0.0, prompt.0.1, prompt.1
        )));
        prompt_state.set_selected(true);

        let tab_body = tab_body.inner(Margin {
            vertical: 0,
            horizontal: 2,
        });

        input.set_cursor_position(tab_body.clone(), frame, prompt_state);
        frame.render_stateful_widget(input, tab_body, prompt_state);
    }
}

fn is_generic_left(key: &KeyEvent) -> bool {
    (matches!(key.code, KeyCode::Char('h') | KeyCode::Left) && key.modifiers.is_empty())
}

fn is_generic_down(key: &KeyEvent) -> bool {
    (matches!(key.code, KeyCode::Char('j') | KeyCode::Down) && key.modifiers.is_empty())
        || (matches!(key.code, KeyCode::Char('n')) && key.modifiers == KeyModifiers::CONTROL)
}

fn is_generic_up(key: &KeyEvent) -> bool {
    (matches!(key.code, KeyCode::Char('k') | KeyCode::Up) && key.modifiers.is_empty())
        || (matches!(key.code, KeyCode::Char('p')) && key.modifiers == KeyModifiers::CONTROL)
}

fn is_generic_right(key: &KeyEvent) -> bool {
    (matches!(key.code, KeyCode::Char('l') | KeyCode::Right) && key.modifiers.is_empty())
}

async fn handle_cmd_buffer<'scope, 'env: 'scope>(
    tui: &mut Tui<'_>,
    c: char,
    #[cfg(unix)] log_writer: &PipeWriter,
    #[cfg(windows)] log_writer: &tokio::sync::mpsc::Sender<super::logs::LogEvent>,
    prompt_writer: &mpsc::Sender<(CheckId, String)>,
    checks_scope: &'scope std::thread::Scope<'scope, 'env>,
) {
    if c != '\n' {
        tui.buffer.push(c);

        if tui.buffer == "gg" {
            tui.check_tab_data.reset_to_top();
            tui.current_selection = CurrentSelection::Tabs;
            tui.buffer.clear();
        }

        return;
    }

    if !tui.buffer.starts_with(":") {
        return;
    }

    let cmd = tui.buffer[1..].split(' ').collect::<Vec<_>>();

    match cmd[..] {
        [action @ ("start" | "stop" | "trigger"), "all"] => {
            let Ok(lock) = tui.checks.read() else {
                return;
            };

            let action = match action {
                "start" => OutboundMessage::Start,
                "stop" => OutboundMessage::Stop,
                "trigger" => OutboundMessage::TriggerNow,
                _ => unreachable!(),
            };

            for hosts in lock.checks.values() {
                for check in hosts.values() {
                    _ = check.1.message_sender.send(action.clone()).await;
                }
            }
        }
        [action @ ("start" | "stop" | "trigger"), id] => {
            let Ok(lock) = tui.checks.read() else {
                return;
            };

            let action = match action {
                "start" => OutboundMessage::Start,
                "stop" => OutboundMessage::Stop,
                "trigger" => OutboundMessage::TriggerNow,
                _ => unreachable!(),
            };

            if let [host, check] = id.split('.').collect::<Vec<_>>()[..] {
                if let Some(host) = lock.checks.get(host)
                    && let Some(check) = host.get(check)
                {
                    _ = check.1.message_sender.send(action).await;
                }
            } else if !id.contains('.') {
                if let Some(host) = lock.checks.get(id) {
                    for check in host.values() {
                        _ = check.1.message_sender.send(action.clone()).await;
                    }
                }
            }
        }
        _ => {}
    }

    tui.buffer.clear();
}

async fn handle_key_event<'scope, 'env: 'scope>(
    tui: &mut Tui<'_>,
    event: Event,
    #[cfg(unix)] log_writer: &PipeWriter,
    #[cfg(windows)] log_writer: &tokio::sync::mpsc::Sender<super::logs::LogEvent>,
    prompt_writer: &mpsc::Sender<(CheckId, String)>,
    checks_scope: &'scope std::thread::Scope<'scope, 'env>,
) -> eyre::Result<ControlFlow<()>> {
    if tui.buffer.starts_with(":")
        && let Event::Key(key) = event
        && let KeyCode::Char(c) = key.code
    {
        handle_cmd_buffer(tui, c, log_writer, prompt_writer, checks_scope).await;

        return Ok(ControlFlow::Continue(()));
    }

    if tui.buffer.starts_with(":")
        && let Event::Key(key) = event
        && let KeyCode::Enter = key.code
    {
        handle_cmd_buffer(tui, '\n', log_writer, prompt_writer, checks_scope).await;

        return Ok(ControlFlow::Continue(()));
    }

    if tui.buffer.starts_with(":")
        && let Event::Key(key) = event
        && let KeyCode::Backspace = key.code
    {
        tui.buffer.pop();

        return Ok(ControlFlow::Continue(()));
    }

    {
        let (final_prompt_input, handled_popup_prompt) = if let Some(input_state) =
            &mut tui.prompt_entry
            && let Event::Key(key) = event
        {
            (
                input_state
                    .handle_keybind(key)
                    .then(|| input_state.input().to_owned()),
                true,
            )
        } else {
            (None, false)
        };
        if let Some(input) = &final_prompt_input
            && let Some(prompt) = tui.current_prompts.get(0).clone()
        {
            let message_sender = tui.checks.read().ok().and_then(|checks| {
                checks.checks.get(&prompt.0.0).and_then(|host| {
                    host.get(&prompt.0.1)
                        .map(|handle| handle.1.message_sender.clone())
                })
            });

            eprintln!("Got here: {}", message_sender.is_some());

            if let Some(message_sender) = message_sender {
                let _ = message_sender
                    .send(OutboundMessage::PromptResponse(input.clone()))
                    .await;
            }
        }
        if final_prompt_input.is_some() {
            tui.prompt_entry = None;
            tui.current_prompts.pop_front();
            if let Some(next_prompt) = tui.current_prompts.get(0) {
                tui.prompt_entry = Some(Default::default());
            }
        }
        if handled_popup_prompt {
            return Ok(ControlFlow::Continue(()));
        }
    }

    if tui.current_selection == CurrentSelection::Tabs {
        let Event::Key(key) = event else {
            return Ok(ControlFlow::Continue(()));
        };

        if key.kind == KeyEventKind::Press {
            if is_generic_down(&key) {
                tui.current_selection = CurrentSelection::TabBody;
            } else {
                match key.code {
                    KeyCode::Char('l') | KeyCode::Right => {
                        tui.buffer.clear();
                        tui.current_tab = tui.current_tab.right();
                    }
                    KeyCode::Char('h') | KeyCode::Left => {
                        tui.buffer.clear();
                        tui.current_tab = tui.current_tab.left();
                    }
                    KeyCode::Char('0') => {
                        tui.buffer.clear();
                        tui.current_tab = Tab::Checks;
                    }
                    KeyCode::Char('$') => {
                        tui.buffer.clear();
                        tui.current_tab = Tab::Exit;
                    }
                    KeyCode::Enter if tui.current_tab == Tab::Exit => {
                        tui.buffer.clear();
                        return Ok(ControlFlow::Break(()));
                    }
                    KeyCode::Char(c) => {
                        handle_cmd_buffer(tui, c, log_writer, prompt_writer, checks_scope).await;
                    }
                    _ => {}
                }
            }
        }

        return Ok(ControlFlow::Continue(()));
    }

    if let Event::Key(key) = event {
        let handled = match tui.current_tab {
            Tab::Checks => checks::handle_keypress(tui, key).await,
            Tab::AddCheck => {
                tui.current_selection = CurrentSelection::Tabs;
                true
            }
            Tab::Settings => {
                tui.current_selection = CurrentSelection::Tabs;
                true
            }
            Tab::Logs => {
                tui.current_selection = CurrentSelection::Tabs;
                true
            }
            Tab::Exit => true,
        };

        if !handled && let KeyCode::Char(c) = key.code {
            handle_cmd_buffer(tui, c, log_writer, prompt_writer, checks_scope).await;
        }
    }

    return Ok(ControlFlow::Continue(()));
}

#[derive(FromRepr, PartialEq, Eq, Clone, Copy)]
enum CurrentSelection {
    Tabs,
    TabBody,
}

#[derive(FromRepr, PartialEq, Eq, Clone, Copy)]
enum Tab {
    Checks,
    AddCheck,
    Settings,
    Logs,
    Exit,
}

impl Tab {
    fn left(self) -> Self {
        match self {
            Self::Checks => Self::Checks,
            Self::AddCheck => Self::Checks,
            Self::Settings => Self::AddCheck,
            Self::Logs => Self::Settings,
            Self::Exit => Self::Logs,
        }
    }

    fn right(self) -> Self {
        match self {
            Self::Checks => Self::AddCheck,
            Self::AddCheck => Self::Settings,
            Self::Settings => Self::Logs,
            Self::Logs => Self::Exit,
            Self::Exit => Self::Exit,
        }
    }
}

struct Tui<'parent> {
    checks: &'parent RwLock<RuntimeDaemonConfig>,
    current_prompts: VecDeque<(CheckId, String)>,
    prompt_entry: Option<TextInputState>,
    current_selection: CurrentSelection,
    current_tab: Tab,
    logs: HashMap<CheckId, Vec<TroubleshooterResult>>,
    check_tab_data: checks::CheckTabData,
    previous_render_time: usize,
    buffer: String,
}
