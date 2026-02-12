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
    style::{Color, Style},
    text::Text,
    widgets::{Block, Clear, Tabs},
};
use strum::FromRepr;
use tokio::sync::{broadcast, mpsc};

use super::{CheckId, RuntimeDaemonConfig, TroubleshooterResult, logs};

mod checks;

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

    let vertical = Layout::vertical([Constraint::Length(3), Constraint::Min(2)]);
    let [tab_header, tab_body] = vertical.areas(frame.area());

    let highlighted_style = Style::new().fg(Color::Yellow);

    let tab_block = if tui.current_selection == CurrentSelection::Tabs {
        Block::bordered().border_style(highlighted_style.clone())
    } else {
        Block::bordered()
    };
    let highlighted_tab_style = if tui.current_selection == CurrentSelection::Tabs {
        Style::new().bg(Color::Yellow)
    } else {
        Style::new().fg(Color::Yellow)
    };

    frame.render_widget(
        &Tabs::new(vec!["Checks", "Add", "Settings", "Logs", "Exit"])
            .block(tab_block)
            .highlight_style(highlighted_tab_style)
            .select(tui.current_tab as usize),
        tab_header,
    );

    let body_block = if tui.current_selection == CurrentSelection::TabBody {
        Block::bordered().border_style(highlighted_style)
    } else {
        Block::bordered()
    };

    let inner_area = body_block.inner(tab_body);

    frame.render_widget(body_block, tab_body);
    frame.render_widget(Clear, inner_area);

    match tui.current_tab {
        Tab::Checks => checks::render(
            tui,
            frame,
            inner_area,
            tui.current_selection == CurrentSelection::TabBody,
        ),
        Tab::AddCheck => {}
        Tab::Settings => {}
        Tab::Logs => {}
        Tab::Exit => {}
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

async fn handle_key_event<'scope, 'env: 'scope>(
    tui: &mut Tui<'_>,
    event: Event,
    #[cfg(unix)] log_writer: &PipeWriter,
    #[cfg(windows)] log_writer: &tokio::sync::mpsc::Sender<super::logs::LogEvent>,
    prompt_writer: &mpsc::Sender<(CheckId, String)>,
    checks_scope: &'scope std::thread::Scope<'scope, 'env>,
) -> eyre::Result<ControlFlow<()>> {
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
                        tui.current_tab = tui.current_tab.right();
                    }
                    KeyCode::Char('h') | KeyCode::Left => {
                        tui.current_tab = tui.current_tab.left();
                    }
                    KeyCode::Enter if tui.current_tab == Tab::Exit => {
                        return Ok(ControlFlow::Break(()));
                    }
                    _ => {}
                }
            }
        }

        return Ok(ControlFlow::Continue(()));
    }

    if let Event::Key(key) = event {
        match tui.current_tab {
            Tab::Checks => checks::handle_keypress(tui, key).await,
            Tab::AddCheck => {
                tui.current_selection = CurrentSelection::Tabs;
            }
            Tab::Settings => {
                tui.current_selection = CurrentSelection::Tabs;
            }
            Tab::Logs => {
                tui.current_selection = CurrentSelection::Tabs;
            }
            Tab::Exit => {}
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
    current_selection: CurrentSelection,
    current_tab: Tab,
    logs: HashMap<CheckId, Vec<TroubleshooterResult>>,
    prompt_entry: PromptEntry,
    check_tab_data: checks::CheckTabData,
    previous_render_time: usize,
}

#[derive(Default)]
struct PromptEntry {
    input: String,
    character_index: usize,
}
