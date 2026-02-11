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

use crossterm::event::{Event, KeyCode, KeyEventKind};
use futures::StreamExt;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    text::Text,
    widgets::{Block, Clear, Tabs},
};
use russh::keys::ssh_key::sec1::der::Length;
use strum::{EnumIter, FromRepr};
use tokio::sync::{broadcast, mpsc};

use super::{CheckId, RuntimeDaemonConfig, TroubleshooterResult, logs};

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
    };

    loop {
        terminal.draw(|frame| render(&tui_state, frame))?;

        tokio::select! {
            Some(Ok(event)) = reader.next() => {
                if let ControlFlow::Break(_) = handle_key_event(&mut tui_state, event)? {
                    break;
                }
            }
            Some((check_id, prompt)) = prompt_reader.recv() => {
                tui_state.current_prompts.push_back((check_id, prompt));
            }
            Some(event) = logs_reader.recv() => {
                // Update events are implicitly handled
                let logs::LogEvent::Result(res) = event else { continue; };
            }
            _ = &mut ctrl_c => {
                break;
            }
            else => {
                break;
            }
        }
    }

    terminal.draw(|frame| {
        frame.render_widget(Clear, frame.area());
        frame.render_widget(Text::raw("Shutting down..."), frame.area());
    })?;

    send_shutdown.send(())?;

    ratatui::restore();
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

fn render(tui: &Tui<'_>, frame: &mut Frame) {
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

    frame.render_widget(body_block, tab_body);
}

fn handle_key_event(tui: &mut Tui<'_>, event: Event) -> eyre::Result<ControlFlow<()>> {
    if tui.current_selection == CurrentSelection::Tabs {
        let Event::Key(key) = event else {
            return Ok(ControlFlow::Continue(()));
        };

        if key.kind == KeyEventKind::Press {
            match key.code {
                KeyCode::Char('l') | KeyCode::Right => {
                    tui.current_tab = tui.current_tab.right();
                }
                KeyCode::Char('h') | KeyCode::Left => {
                    tui.current_tab = tui.current_tab.left();
                }
                KeyCode::Char('j') | KeyCode::Down => {
                    tui.current_selection = CurrentSelection::TabBody;
                }
                KeyCode::Enter if tui.current_tab == Tab::Exit => {
                    return Ok(ControlFlow::Break(()));
                }
                _ => {}
            }
        }

        return Ok(ControlFlow::Continue(()));
    }

    if let Event::Key(key) = event
        && key.kind == KeyEventKind::Press
        && let KeyCode::Char('k') | KeyCode::Up = key.code
    {
        tui.current_selection = CurrentSelection::Tabs;

        return Ok(ControlFlow::Continue(()));
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
}

#[derive(Default)]
struct PromptEntry {
    input: String,
    character_index: usize,
}
