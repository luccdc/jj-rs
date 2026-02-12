use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    Frame,
    layout::{Margin, Rect},
    style::{Color, Style, Styled, Stylize, palette::tailwind::NEUTRAL},
    text::{Line, Text},
    widgets::{Block, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
};
use strum::FromRepr;

use crate::checks::CheckResultType;

use super::{
    super::check_thread::OutboundMessage, CheckId, is_generic_down, is_generic_left,
    is_generic_right, is_generic_up,
};

#[derive(Debug)]
struct OpenResultState {
    index: usize,
    extra_details_render: Vec<usize>,
}

#[derive(Default, Debug)]
struct OpenCheckState {
    viewing_all: bool,
}

#[derive(Default, FromRepr, PartialEq, Eq, Debug)]
enum CheckControls {
    #[default]
    RunOnce,
    StartStop,
    ShowCheckConfig,
    ShowHideAllResults,
}

impl CheckControls {
    fn left(&self) -> Self {
        match self {
            Self::RunOnce => Self::RunOnce,
            Self::StartStop => Self::RunOnce,
            Self::ShowCheckConfig => Self::StartStop,
            Self::ShowHideAllResults => Self::ShowCheckConfig,
        }
    }

    fn right(&self) -> Self {
        match self {
            Self::RunOnce => Self::StartStop,
            Self::StartStop => Self::ShowCheckConfig,
            Self::ShowCheckConfig => Self::ShowHideAllResults,
            Self::ShowHideAllResults => Self::ShowHideAllResults,
        }
    }
}

#[derive(Default, PartialEq, Eq, Debug)]
enum CheckHighlight {
    #[default]
    Check,
    Controls(CheckControls),
    RecentResults(usize),
    BadResults(usize),
    AllResults(usize),
}

#[derive(Clone)]
struct ShowCheckConfigState {
    id: CheckId,
    vertical_scroll: usize,
    vertical_scroll_state: ScrollbarState,
    horizontal_scroll: usize,
    horizontal_scroll_state: ScrollbarState,
}

struct ShowResultState {
    id: CheckId,
    result_id: usize,
    vertical_scroll: usize,
    vertical_scroll_state: ScrollbarState,
    horizontal_scroll: usize,
    horizontal_scroll_state: ScrollbarState,
}

struct ShowResultStepState {
    step_id: usize,
    vertical_scroll: usize,
    vertical_scroll_state: ScrollbarState,
    horizontal_scroll: usize,
    horizontal_scroll_state: ScrollbarState,
}

#[derive(Default)]
pub struct CheckTabData {
    vertical_scrollbar_position: usize,
    horizontal_scrollbar_position: usize,
    vertical_scrollbar_state: ScrollbarState,
    horizontal_scrollbar_state: ScrollbarState,
    open_checks: HashMap<CheckId, OpenCheckState>,
    current_highlight_state: CheckHighlight,
    current_highlight_index: usize,
    current_result_view: Option<ShowResultState>,
    current_step_view: Option<ShowResultStepState>,
    last_rendered_check_ids: Vec<CheckId>,
    check_config_to_show: Option<ShowCheckConfigState>,
}

impl CheckTabData {
    pub fn reset_to_top(&mut self) {
        self.current_highlight_index = 0;
        self.current_highlight_state = CheckHighlight::Check;
    }
}

fn get_check_json(tui: &super::Tui<'_>, config: CheckId) -> Option<serde_json::Value> {
    let lock = tui.checks.read().ok()?;
    let host = lock.checks.get(&config.0)?;
    let check = host.get(&config.1)?;

    serde_json::to_value(&check.0)
        .ok()
        .and_then(|v| v.as_object().and_then(|o| o.values().next().cloned()))
}

fn render_check_config(
    check_json: serde_json::Value,
    frame: &mut Frame,
    inner_area: Rect,
    config: &mut ShowCheckConfigState,
) {
    let serde_json::Value::Object(obj) = check_json else {
        return;
    };

    let max_width = obj.keys().map(String::len).max().unwrap_or_default();

    let styles = [NEUTRAL.c950, NEUTRAL.c700];

    let lines = obj
        .into_iter()
        .enumerate()
        .map(|(i, (key, val))| {
            Line::default()
                .spans(vec![
                    format!("{:<max_width$}: ", format!("{key}")).dark_gray(),
                    serde_json::to_string(&val).unwrap_or_default().into(),
                ])
                .bg(styles[i % 2])
        })
        .collect::<Vec<_>>();

    let max_width = lines.iter().map(Line::width).max().unwrap_or_default() as isize;
    let depth = lines.len() as isize;

    let display_width = inner_area.width as isize;
    let display_height = inner_area.height as isize;

    let width = (max_width - display_width).max(0) as usize;
    let height = (depth - display_height).max(0) as usize;

    config.horizontal_scroll_state = config.horizontal_scroll_state.content_length(width);
    config.vertical_scroll_state = config.vertical_scroll_state.content_length(height);

    frame.render_widget(
        Paragraph::new(lines).scroll((
            config.vertical_scroll as u16,
            config.horizontal_scroll as u16,
        )),
        inner_area,
    );

    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight),
        inner_area.clone().inner(Margin {
            vertical: 2,
            horizontal: 0,
        }),
        &mut config.vertical_scroll_state,
    );

    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::HorizontalBottom),
        inner_area.clone().inner(Margin {
            vertical: 0,
            horizontal: 2,
        }),
        &mut config.horizontal_scroll_state,
    );
}

pub fn render(tui: &mut super::Tui<'_>, frame: &mut Frame, inner_area: Rect, tab_selected: bool) {
    let mut checks = {
        let checks = match tui.checks.read() {
            Err(e) => {
                frame.render_widget(
                    Text::raw(format!("Failed to retrieve checks! {e:?}")),
                    inner_area,
                );
                return;
            }
            Ok(v) => v,
        };

        checks
            .checks
            .iter()
            .flat_map(|(host, checks)| {
                checks
                    .iter()
                    .map(|(name, (check, handle))| {
                        (
                            super::CheckId(Arc::clone(&host), Arc::clone(&name)),
                            check.clone(),
                            handle.currently_running.load(Ordering::Acquire),
                            handle.started.load(Ordering::Acquire),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    };

    checks.sort_by_key(|(id, _, _, _)| id.clone());

    tui.check_tab_data.last_rendered_check_ids =
        checks.iter().map(|(id, _, _, _)| id.clone()).collect();

    let display_lines = checks
        .into_iter()
        .enumerate()
        .flat_map(|(i, (id, check, currently_running, started))| {
            let open_state = tui.check_tab_data.open_checks.get(&id).clone();

            let results = tui.logs.get(&id);

            let current_selected = i == tui.check_tab_data.current_highlight_index && tab_selected;

            let check_line_style = if current_selected
                && tui.check_tab_data.current_highlight_state == CheckHighlight::Check
            {
                Style::new().underlined()
            } else {
                Style::new()
            };

            let mut check_render = vec![Line::default().spans(vec![
                if open_state.is_some() {
                    " ↓ "
                } else {
                    " → "
                }
                .into(),
                format!("{}", check.display_name()).set_style(check_line_style.dark_gray()),
                format!(": {}.{} (", id.0, id.1).set_style(check_line_style),
                if currently_running {
                    "RUNNING".set_style(check_line_style.bg(Color::Green))
                } else {
                    "WAITING".set_style(check_line_style.yellow())
                },
                ", ".set_style(check_line_style),
                match results
                    .and_then(|logs| logs.iter().next_back())
                    .map(|result| result.overall_result)
                {
                    Some(CheckResultType::NotRun) | None => {
                        "NOT RUN".set_style(check_line_style.dark_gray())
                    }
                    Some(CheckResultType::Success) => {
                        "PASS".set_style(check_line_style.bg(Color::Green))
                    }
                    Some(CheckResultType::Failure) => {
                        "FAIL".set_style(check_line_style.bg(Color::Red))
                    }
                },
                ", ".set_style(check_line_style),
                if started {
                    "ENABLED".set_style(check_line_style.bg(Color::Green))
                } else {
                    "DISABLED".set_style(check_line_style.dark_gray())
                },
                ")".set_style(check_line_style),
            ])];

            if let Some(open_state) = open_state {
                let logs = tui.logs.get(&id);

                {
                    let controls_selected = current_selected
                        && matches!(
                            tui.check_tab_data.current_highlight_state,
                            CheckHighlight::Controls(_)
                        );

                    let controls_style = if controls_selected {
                        Style::new().underlined()
                    } else {
                        Style::new()
                    };

                    let controls_runonce_style = if current_selected
                        && tui.check_tab_data.current_highlight_state
                            == CheckHighlight::Controls(CheckControls::RunOnce)
                    {
                        if currently_running {
                            Style::new().bg(Color::DarkGray).underlined()
                        } else {
                            Style::new().bg(Color::Yellow).black().underlined()
                        }
                    } else if controls_selected {
                        Style::new().underlined()
                    } else {
                        Style::new()
                    };

                    let controls_startstop_style = if current_selected
                        && tui.check_tab_data.current_highlight_state
                            == CheckHighlight::Controls(CheckControls::StartStop)
                    {
                        Style::new().bg(Color::Yellow).black().underlined()
                    } else if controls_selected {
                        Style::new().underlined()
                    } else {
                        Style::new()
                    };

                    let controls_showconf_style = if current_selected
                        && tui.check_tab_data.current_highlight_state
                            == CheckHighlight::Controls(CheckControls::ShowCheckConfig)
                    {
                        Style::new().bg(Color::Yellow).black().underlined()
                    } else if controls_selected {
                        Style::new().underlined()
                    } else {
                        Style::new()
                    };

                    let controls_showhide_style = if current_selected
                        && tui.check_tab_data.current_highlight_state
                            == CheckHighlight::Controls(CheckControls::ShowHideAllResults)
                    {
                        Style::new().bg(Color::Yellow).black().underlined()
                    } else if controls_selected {
                        Style::new().underlined()
                    } else {
                        Style::new()
                    };

                    check_render.push(Line::default().spans(vec![
                        "     ".into(),
                        "Run Once".set_style(controls_runonce_style),
                        " | ".set_style(controls_style.clone()),
                        if started { "Stop" } else { "Start" }
                            .set_style(controls_startstop_style),
                        " | ".set_style(controls_style.clone()),
                        "Show Config".set_style(controls_showconf_style),
                        " | ".set_style(controls_style.clone()),
                        if open_state.viewing_all {
                            "Hide extra results"
                        } else {
                            "Show all results"
                        }
                        .set_style(controls_showhide_style),
                    ]))
                }

                {
                    check_render.push(
                        Line::default().spans(vec!["    ".into(), "Recent check results".bold()]),
                    );

                    let (i, style) = if current_selected
                        && let CheckHighlight::RecentResults(i) =
                            &tui.check_tab_data.current_highlight_state
                    {
                        (*i, Style::new().underlined())
                    } else {
                        (0, Style::new())
                    };

                    if let Some(logs) = &logs
                        && logs.len() > 0
                    {
                        let logs = logs.iter().rev().enumerate().take(5);

                        for (j, log) in logs {
                            let style = if i == j { style } else { Style::new() };

                            check_render.push(Line::default().spans(vec![
                                "      ".into(),
                                match log.overall_result {
                                    CheckResultType::Success => {
                                        "PASS".set_style(style.bg(Color::Green))
                                    }
                                    CheckResultType::Failure => {
                                        "FAIL".set_style(style.bg(Color::Red))
                                    }
                                    CheckResultType::NotRun => {
                                        "NOT RUN".set_style(style.dark_gray())
                                    }
                                },
                                format!(" {} ", log.timestamp).set_style(style),
                            ]))
                        }
                    } else {
                        check_render.push(Line::default().spans(vec![
                            "      ".into(),
                            "No recent check results!".set_style(style.dark_gray()),
                        ]));
                    }
                }

                {
                    check_render.push(
                        Line::default()
                            .spans(vec!["    ".into(), "Recent failed check results".bold()]),
                    );

                    let (i, style) = if current_selected
                        && let CheckHighlight::BadResults(i) =
                            &tui.check_tab_data.current_highlight_state
                    {
                        (*i, Style::new().underlined())
                    } else {
                        (0, Style::new())
                    };

                    if let Some(logs) = &logs
                        && logs
                            .iter()
                            .filter(|r| r.overall_result == CheckResultType::Failure)
                            .next()
                            .is_some()
                    {
                        let logs = logs
                            .iter()
                            .rev()
                            .filter(|r| r.overall_result == CheckResultType::Failure)
                            .enumerate()
                            .take(5);

                        for (j, log) in logs {
                            let style = if i == j { style } else { Style::new() };

                            check_render.push(Line::default().spans(vec![
                                "      ".into(),
                                match log.overall_result {
                                    CheckResultType::Success => {
                                        "PASS".set_style(style.bg(Color::Green))
                                    }
                                    CheckResultType::Failure => {
                                        "FAIL".set_style(style.bg(Color::Red))
                                    }
                                    CheckResultType::NotRun => {
                                        "NOT RUN".set_style(style.dark_gray())
                                    }
                                },
                                format!(" {} ", log.timestamp).set_style(style),
                            ]))
                        }
                    } else {
                        check_render.push(Line::default().spans(vec![
                            "      ".into(),
                            "No recent failed check results!".set_style(style.dark_gray()),
                        ]));
                    }
                }

                if open_state.viewing_all {
                    check_render
                        .push(Line::default().spans(vec!["    ".into(), "All results".bold()]));

                    let (i, style) = if current_selected
                        && let CheckHighlight::AllResults(i) =
                            &tui.check_tab_data.current_highlight_state
                    {
                        (*i, Style::new().underlined())
                    } else {
                        (0, Style::new())
                    };

                    if let Some(logs) = &logs
                        && logs.len() > 0
                    {
                        let logs = logs.iter().rev().enumerate();

                        for (j, log) in logs {
                            let style = if i == j { style } else { Style::new() };

                            check_render.push(Line::default().spans(vec![
                                "      ".into(),
                                match log.overall_result {
                                    CheckResultType::Success => {
                                        "PASS".set_style(style.bg(Color::Green))
                                    }
                                    CheckResultType::Failure => {
                                        "FAIL".set_style(style.bg(Color::Red))
                                    }
                                    CheckResultType::NotRun => {
                                        "NOT RUN".set_style(style.dark_gray())
                                    }
                                },
                                format!(" {} ", log.timestamp).set_style(style),
                            ]))
                        }
                    } else {
                        check_render.push(Line::default().spans(vec![
                            "      ".into(),
                            "No recent failed check results!".set_style(style.dark_gray()),
                        ]));
                    }
                }
            }

            check_render
        })
        .collect::<Vec<_>>();

    let display_width = inner_area.width as isize;
    let display_height = inner_area.height as isize;

    let max_width = display_lines
        .iter()
        .map(Line::width)
        .max()
        .unwrap_or_default() as isize;
    let max_depth = display_lines.len() as isize;

    let max_width = (max_width - display_width).max(0) as usize;
    let max_height = (max_depth - display_height).max(0) as usize;

    tui.check_tab_data.horizontal_scrollbar_state = tui
        .check_tab_data
        .horizontal_scrollbar_state
        .content_length(max_width);
    tui.check_tab_data.vertical_scrollbar_state = tui
        .check_tab_data
        .vertical_scrollbar_state
        .content_length(max_height);

    let paragraph = Paragraph::new(display_lines).scroll((
        tui.check_tab_data.vertical_scrollbar_position as u16,
        tui.check_tab_data.horizontal_scrollbar_position as u16,
    ));

    frame.render_widget(paragraph, inner_area.clone());

    frame.render_stateful_widget(
        Scrollbar::new(ratatui::widgets::ScrollbarOrientation::VerticalRight),
        inner_area.clone().inner(Margin {
            vertical: 2,
            horizontal: 0,
        }),
        &mut tui.check_tab_data.vertical_scrollbar_state,
    );
    frame.render_stateful_widget(
        Scrollbar::new(ratatui::widgets::ScrollbarOrientation::HorizontalBottom).thumb_symbol("🬋"),
        inner_area.clone().inner(Margin {
            vertical: 0,
            horizontal: 2,
        }),
        &mut tui.check_tab_data.horizontal_scrollbar_state,
    );

    // this way avoids the borrow checker; we want to borrow immutably later
    // but can't borrow tui (even immutably) if we have the mutable reference
    let json = tui
        .check_tab_data
        .check_config_to_show
        .as_ref()
        .map(|c| c.id.clone())
        .and_then(|id| get_check_json(tui, id));
    if let Some(show_config) = &mut tui.check_tab_data.check_config_to_show
        && let Some(json) = json
    {
        let area = inner_area.clone().inner(Margin {
            vertical: 2,
            horizontal: 5,
        });
        frame.render_widget(Clear, area.clone());
        let block = Block::bordered();
        frame.render_widget(&block, area.clone());

        let inner_area = block.inner(area);

        render_check_config(json, frame, inner_area, show_config);
    }
}

pub async fn handle_keypress(tui: &mut super::Tui<'_>, key: KeyEvent) -> bool {
    let KeyEventKind::Press = key.kind else {
        return false;
    };

    let Some(current_check_selected) = tui
        .check_tab_data
        .last_rendered_check_ids
        .get(tui.check_tab_data.current_highlight_index)
    else {
        return false;
    };

    if let Some(show_config) = &mut tui.check_tab_data.check_config_to_show {
        if let KeyCode::Char('0') = key.code {
            show_config.horizontal_scroll = 0;
            show_config.horizontal_scroll_state = show_config
                .horizontal_scroll_state
                .position(show_config.horizontal_scroll);
        } else if let KeyCode::Char('_') = key.code {
            let _ = show_config.vertical_scroll.saturating_sub(1);
            show_config.vertical_scroll_state = show_config
                .vertical_scroll_state
                .position(show_config.vertical_scroll);
            show_config.horizontal_scroll = 0;
            show_config.horizontal_scroll_state = show_config
                .horizontal_scroll_state
                .position(show_config.horizontal_scroll);
        } else if is_generic_down(&key) {
            let _ = show_config.vertical_scroll.saturating_add(1);
            show_config.vertical_scroll_state = show_config
                .vertical_scroll_state
                .position(show_config.vertical_scroll);
        } else if is_generic_up(&key) {
            let _ = show_config.vertical_scroll.saturating_sub(1);
            show_config.vertical_scroll_state = show_config
                .vertical_scroll_state
                .position(show_config.vertical_scroll);
        } else if is_generic_left(&key) {
            let _ = show_config.horizontal_scroll.saturating_sub(1);
            show_config.horizontal_scroll_state = show_config
                .horizontal_scroll_state
                .position(show_config.horizontal_scroll);
        } else if is_generic_right(&key) {
            let _ = show_config.horizontal_scroll.saturating_add(1);
            show_config.horizontal_scroll_state = show_config
                .horizontal_scroll_state
                .position(show_config.horizontal_scroll);
        } else {
            tui.check_tab_data.check_config_to_show = None;
        }
        tui.buffer.clear();
        return true;
    }

    if tui.check_tab_data.current_highlight_state == CheckHighlight::Check
        && let KeyCode::Enter | KeyCode::Char(' ') = key.code
    {
        if tui
            .check_tab_data
            .open_checks
            .contains_key(&current_check_selected)
        {
            tui.check_tab_data
                .open_checks
                .remove(&current_check_selected);
        } else {
            tui.check_tab_data
                .open_checks
                .insert(current_check_selected.clone(), Default::default());
        }
        tui.buffer.clear();
        set_vertical_scroll(tui);
        return true;
    }

    if let Ok(v) = tui.buffer.parse::<usize>() {
        let mut handled = false;
        for _ in 0..v {
            handled |= handle_movement(tui, &key);
        }
        if handled {
            tui.buffer.clear();
            return true;
        }
    } else {
        if handle_movement(tui, &key) {
            tui.buffer.clear();
            return true;
        }
    }
    if handle_selects(tui, &key).await {
        tui.buffer.clear();
        return true;
    }
    return false;
}

async fn handle_selects(tui: &mut super::Tui<'_>, key: &KeyEvent) -> bool {
    let Some(current_check_selected) = tui
        .check_tab_data
        .last_rendered_check_ids
        .get(tui.check_tab_data.current_highlight_index)
    else {
        return false;
    };

    if let Some(open_state) = tui
        .check_tab_data
        .open_checks
        .get_mut(&current_check_selected)
        && let CheckHighlight::Controls(control) = &tui.check_tab_data.current_highlight_state
        && let KeyCode::Char(' ') | KeyCode::Enter = key.code
    {
        match *control {
            CheckControls::RunOnce => {
                let Ok(lock) = tui.checks.read() else {
                    return false;
                };

                let Some(host) = lock.checks.get(&current_check_selected.0) else {
                    return false;
                };
                let Some(check) = host.get(&current_check_selected.1) else {
                    return false;
                };

                if check.1.currently_running.load(Ordering::Acquire) {
                    return false;
                }

                let _ = check
                    .1
                    .message_sender
                    .send(OutboundMessage::TriggerNow)
                    .await;
            }
            CheckControls::StartStop => {
                let Ok(lock) = tui.checks.read() else {
                    return false;
                };

                let Some(host) = lock.checks.get(&current_check_selected.0) else {
                    return false;
                };
                let Some(check) = host.get(&current_check_selected.1) else {
                    return false;
                };

                if check.1.started.load(Ordering::Acquire) {
                    let _ = check.1.message_sender.send(OutboundMessage::Stop).await;
                } else {
                    let _ = check.1.message_sender.send(OutboundMessage::Start).await;
                }
            }
            CheckControls::ShowCheckConfig => {
                tui.check_tab_data.check_config_to_show = Some(ShowCheckConfigState {
                    id: current_check_selected.clone(),
                    vertical_scroll: 0,
                    vertical_scroll_state: ScrollbarState::default(),
                    horizontal_scroll: 0,
                    horizontal_scroll_state: ScrollbarState::default(),
                });
            }
            CheckControls::ShowHideAllResults => {
                open_state.viewing_all = !open_state.viewing_all;
            }
        }
        return true;
    }

    return false;
}

fn get_vertical_position(tui: &super::Tui<'_>, check_index: usize) -> usize {
    let Some(current_check_selected) = tui.check_tab_data.last_rendered_check_ids.get(check_index)
    else {
        return 0;
    };

    let Some(current_check_open) = tui.check_tab_data.open_checks.get(&current_check_selected)
    else {
        return 1;
    };

    let Some(logs) = tui.logs.get(&current_check_selected) else {
        return if current_check_open.viewing_all { 6 } else { 8 };
    };

    let base_height = 4
        + logs.len().min(5).max(1)
        + logs
            .iter()
            .filter(|c| c.overall_result == CheckResultType::Failure)
            .count()
            .min(5)
            .max(1);

    if current_check_open.viewing_all {
        base_height + logs.len().max(1)
    } else {
        base_height
    }
}

fn set_vertical_scroll(tui: &mut super::Tui<'_>) {
    let previous_checks_height = (0..tui.check_tab_data.current_highlight_index)
        .map(|i| get_vertical_position(tui, i))
        .sum::<usize>();

    let Some(current_check_selected) = tui
        .check_tab_data
        .last_rendered_check_ids
        .get(tui.check_tab_data.current_highlight_index)
    else {
        return;
    };

    let current_check_open = tui.check_tab_data.open_checks.get(&current_check_selected);

    let logs = tui.logs.get(&current_check_selected);

    let current_position = previous_checks_height
        + match (
            &tui.check_tab_data.current_highlight_state,
            current_check_open,
            logs,
        ) {
            (CheckHighlight::Check, _, _) => 1,
            (CheckHighlight::Controls(_), _, _) => 2,
            (CheckHighlight::RecentResults(i), _, _) => 4 + i,
            (CheckHighlight::BadResults(i), _, Some(logs)) => 5 + logs.len().min(5).max(1) + i,
            (CheckHighlight::AllResults(i), Some(open), Some(logs)) if open.viewing_all => {
                6 + logs.len().min(5).max(1)
                    + logs
                        .iter()
                        .filter(|r| r.overall_result == CheckResultType::Failure)
                        .count()
                        .min(5)
                        .max(1)
                    + i
            }
            _ => {
                return;
            }
        };

    let Ok(size) = crossterm::terminal::window_size() else {
        return;
    };

    // 6: 3 for tab header, 2 for borders of tab area, 1 for command buffer
    let scroll_area = size.rows - 6;

    if current_position < 5 {
        tui.check_tab_data.vertical_scrollbar_position = 0;
        tui.check_tab_data.vertical_scrollbar_state = tui
            .check_tab_data
            .vertical_scrollbar_state
            .position(tui.check_tab_data.vertical_scrollbar_position);
    }

    let vsp = tui.check_tab_data.vertical_scrollbar_position as isize;
    let current_position = current_position as isize;
    let scroll_area = scroll_area as isize;

    if current_position - vsp < 5 {
        tui.check_tab_data.vertical_scrollbar_position = 0 as usize;
        tui.check_tab_data.vertical_scrollbar_state = tui
            .check_tab_data
            .vertical_scrollbar_state
            .position(tui.check_tab_data.vertical_scrollbar_position);
        return;
    }

    if (scroll_area + vsp) - current_position < 5 {
        tui.check_tab_data.vertical_scrollbar_position =
            (current_position + 5 - scroll_area) as usize;
        tui.check_tab_data.vertical_scrollbar_state = tui
            .check_tab_data
            .vertical_scrollbar_state
            .position(tui.check_tab_data.vertical_scrollbar_position);
    }
}

fn handle_movement(tui: &mut super::Tui<'_>, key: &KeyEvent) -> bool {
    if tui.check_tab_data.current_highlight_index == 0
        && tui.check_tab_data.current_highlight_state == CheckHighlight::Check
        && is_generic_up(&key)
    {
        tui.current_selection = super::CurrentSelection::Tabs;
        tui.buffer.clear();
        set_vertical_scroll(tui);
        return true;
    }

    let Some(current_check_selected) = tui
        .check_tab_data
        .last_rendered_check_ids
        .get(tui.check_tab_data.current_highlight_index)
    else {
        return false;
    };

    if let Some(open_state) = tui.check_tab_data.open_checks.get(&current_check_selected) {
        if is_generic_up(&key)
            && let CheckHighlight::Check = tui.check_tab_data.current_highlight_state
        {
            if let Some(prev_check_id) = tui
                .check_tab_data
                .last_rendered_check_ids
                .get(tui.check_tab_data.current_highlight_index - 1)
                && let Some(open_state) = tui.check_tab_data.open_checks.get(&prev_check_id)
            {
                if open_state.viewing_all {
                    let logs_length = tui
                        .logs
                        .get(prev_check_id)
                        .map(|l| l.len())
                        .unwrap_or_default();

                    tui.check_tab_data.current_highlight_state =
                        CheckHighlight::AllResults(logs_length - 1);
                } else {
                    let logs_length = tui
                        .logs
                        .get(prev_check_id)
                        .map(|l| {
                            l.iter()
                                .filter(|r| r.overall_result == CheckResultType::Failure)
                                .count()
                        })
                        .unwrap_or_default()
                        .clamp(0, 4);

                    tui.check_tab_data.current_highlight_state =
                        CheckHighlight::BadResults(logs_length);
                }
            } else {
                tui.check_tab_data.current_highlight_state = CheckHighlight::Check;
            }
            tui.check_tab_data.current_highlight_index -= 1;
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_down(&key)
            && let CheckHighlight::Check = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state =
                CheckHighlight::Controls(CheckControls::RunOnce);
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_up(&key)
            && let CheckHighlight::Controls(_) = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::Check;
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_down(&key)
            && let CheckHighlight::Controls(_) = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::RecentResults(0);
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_left(&key)
            && let CheckHighlight::Controls(control) = &tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::Controls(control.left());
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_left(key) && tui.check_tab_data.horizontal_scrollbar_position == 0 {
            tui.check_tab_data.current_highlight_state = CheckHighlight::Check;
            tui.check_tab_data
                .open_checks
                .remove(current_check_selected);
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_right(&key)
            && let CheckHighlight::Controls(control) = &tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::Controls(control.right());
            set_vertical_scroll(tui);
            return true;
        }

        if let KeyCode::Char('0') = key.code
            && let CheckHighlight::Controls(_) = &tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state =
                CheckHighlight::Controls(CheckControls::RunOnce);
            set_vertical_scroll(tui);
            return true;
        }

        if let KeyCode::Char('$') = key.code
            && let CheckHighlight::Controls(_) = &tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state =
                CheckHighlight::Controls(CheckControls::ShowHideAllResults);
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_up(&key)
            && let CheckHighlight::RecentResults(0) = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state =
                CheckHighlight::Controls(CheckControls::RunOnce);
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_up(&key)
            && let CheckHighlight::RecentResults(i) = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::RecentResults(i - 1);
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_down(&key)
            && let CheckHighlight::RecentResults(i) = tui.check_tab_data.current_highlight_state
        {
            let logs_length = tui
                .logs
                .get(current_check_selected)
                .map(|l| l.len())
                .unwrap_or_default();

            if i >= logs_length.clamp(0, 4) {
                tui.check_tab_data.current_highlight_state = CheckHighlight::BadResults(0);
            } else {
                tui.check_tab_data.current_highlight_state = CheckHighlight::RecentResults(i + 1);
            }
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_up(&key)
            && let CheckHighlight::BadResults(0) = tui.check_tab_data.current_highlight_state
        {
            let logs_length = tui
                .logs
                .get(current_check_selected)
                .map(|l| l.len())
                .unwrap_or_default();

            tui.check_tab_data.current_highlight_state =
                CheckHighlight::RecentResults(logs_length.clamp(0, 4));
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_up(&key)
            && let CheckHighlight::BadResults(i) = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::BadResults(i - 1);
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_down(&key)
            && let CheckHighlight::BadResults(i) = tui.check_tab_data.current_highlight_state
        {
            let logs_length = tui
                .logs
                .get(current_check_selected)
                .map(|l| {
                    l.iter()
                        .filter(|r| r.overall_result == CheckResultType::Failure)
                        .count()
                })
                .unwrap_or_default();

            if i >= logs_length.clamp(0, 4) {
                if open_state.viewing_all {
                    tui.check_tab_data.current_highlight_state = CheckHighlight::AllResults(0);
                } else if tui.check_tab_data.current_highlight_index + 1
                    < tui.check_tab_data.last_rendered_check_ids.len()
                {
                    tui.check_tab_data.current_highlight_state = CheckHighlight::Check;
                    tui.check_tab_data.current_highlight_index += 1;
                }
            } else {
                tui.check_tab_data.current_highlight_state = CheckHighlight::BadResults(i + 1);
            }
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_up(&key)
            && let CheckHighlight::AllResults(0) = tui.check_tab_data.current_highlight_state
        {
            let logs_length = tui
                .logs
                .get(current_check_selected)
                .map(|l| {
                    l.iter()
                        .filter(|r| r.overall_result == CheckResultType::Failure)
                        .count()
                })
                .unwrap_or_default()
                .clamp(0, 4);

            tui.check_tab_data.current_highlight_state = CheckHighlight::BadResults(logs_length);

            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_up(&key)
            && let CheckHighlight::AllResults(i) = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::AllResults(i - 1);
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_down(&key)
            && let CheckHighlight::AllResults(i) = tui.check_tab_data.current_highlight_state
        {
            let logs_length = tui
                .logs
                .get(current_check_selected)
                .map(|l| l.len())
                .unwrap_or_default();

            if i + 1 >= logs_length {
                if tui.check_tab_data.current_highlight_index + 1
                    < tui.check_tab_data.last_rendered_check_ids.len()
                {
                    tui.check_tab_data.current_highlight_state = CheckHighlight::Check;
                    tui.check_tab_data.current_highlight_index += 1;
                }
            } else {
                tui.check_tab_data.current_highlight_state = CheckHighlight::AllResults(i + 1);
            }
            set_vertical_scroll(tui);
            return true;
        }
    } else {
        if is_generic_down(&key) {
            tui.check_tab_data.current_highlight_index =
                (1 + tui.check_tab_data.current_highlight_index)
                    .clamp(0, tui.check_tab_data.last_rendered_check_ids.len() - 1);
            set_vertical_scroll(tui);
            return true;
        }

        if is_generic_up(&key) {
            if let Some(prev_check_id) = tui
                .check_tab_data
                .last_rendered_check_ids
                .get(tui.check_tab_data.current_highlight_index - 1)
                && let Some(open_state) = tui.check_tab_data.open_checks.get(&prev_check_id)
            {
                if open_state.viewing_all {
                    let logs_length = tui
                        .logs
                        .get(prev_check_id)
                        .map(|l| l.len())
                        .unwrap_or_default();

                    tui.check_tab_data.current_highlight_state =
                        CheckHighlight::AllResults(logs_length - 1);
                } else {
                    let logs_length = tui
                        .logs
                        .get(prev_check_id)
                        .map(|l| {
                            l.iter()
                                .filter(|r| r.overall_result == CheckResultType::Failure)
                                .count()
                        })
                        .unwrap_or_default()
                        .clamp(0, 4);

                    tui.check_tab_data.current_highlight_state =
                        CheckHighlight::BadResults(logs_length);
                }
            } else {
                tui.check_tab_data.current_highlight_state = CheckHighlight::Check;
            }
            tui.check_tab_data.current_highlight_index -= 1;
            set_vertical_scroll(tui);
            return true;
        }
    }

    if let KeyCode::Char('h') | KeyCode::Left = key.code {
        tui.check_tab_data.horizontal_scrollbar_position = tui
            .check_tab_data
            .horizontal_scrollbar_position
            .saturating_sub(1);
        tui.check_tab_data.horizontal_scrollbar_state = tui
            .check_tab_data
            .horizontal_scrollbar_state
            .position(tui.check_tab_data.horizontal_scrollbar_position);
        set_vertical_scroll(tui);
        return true;
    }
    if let KeyCode::Char('l') | KeyCode::Right = key.code {
        tui.check_tab_data.horizontal_scrollbar_position = tui
            .check_tab_data
            .horizontal_scrollbar_position
            .saturating_add(1);
        tui.check_tab_data.horizontal_scrollbar_state = tui
            .check_tab_data
            .horizontal_scrollbar_state
            .position(tui.check_tab_data.horizontal_scrollbar_position);
        set_vertical_scroll(tui);
        return true;
    }

    return false;
}
