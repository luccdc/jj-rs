use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    Frame,
    layout::{Margin, Rect},
    style::{Color, Style, Styled, Stylize},
    text::{Line, Text},
    widgets::{Paragraph, Scrollbar, ScrollbarState},
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
    ShowHideAllResults,
}

impl CheckControls {
    fn left(&self) -> Self {
        match self {
            Self::RunOnce => Self::RunOnce,
            Self::StartStop => Self::RunOnce,
            Self::ShowHideAllResults => Self::StartStop,
        }
    }

    fn right(&self) -> Self {
        match self {
            Self::RunOnce => Self::StartStop,
            Self::StartStop => Self::ShowHideAllResults,
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

#[derive(Default)]
pub struct CheckTabData {
    vertical_scrollbar_position: usize,
    horizontal_scrollbar_position: usize,
    vertical_scrollbar_state: ScrollbarState,
    horizontal_scrollbar_state: ScrollbarState,
    open_checks: HashMap<CheckId, OpenCheckState>,
    current_highlight_state: CheckHighlight,
    current_highlight_index: usize,
    current_result_view: Option<(CheckId, usize)>,
    current_step_view: Option<usize>,
    last_rendered_check_ids: Vec<CheckId>,
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

    let max_width = display_lines
        .iter()
        .map(Line::width)
        .max()
        .unwrap_or_default();
    let max_depth = display_lines.len();

    tui.check_tab_data.horizontal_scrollbar_state = tui
        .check_tab_data
        .horizontal_scrollbar_state
        .content_length(max_width);
    tui.check_tab_data.vertical_scrollbar_state = tui
        .check_tab_data
        .vertical_scrollbar_state
        .content_length(max_depth);

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
        Scrollbar::new(ratatui::widgets::ScrollbarOrientation::HorizontalBottom),
        inner_area.clone().inner(Margin {
            vertical: 0,
            horizontal: 2,
        }),
        &mut tui.check_tab_data.horizontal_scrollbar_state,
    );
}

pub async fn handle_keypress(tui: &mut super::Tui<'_>, key: KeyEvent) {
    let KeyEventKind::Press = key.kind else {
        return;
    };

    if tui.check_tab_data.current_highlight_index == 0
        && tui.check_tab_data.current_highlight_state == CheckHighlight::Check
        && is_generic_up(&key)
    {
        tui.current_selection = super::CurrentSelection::Tabs;
        return;
    }

    let Some(current_check_selected) = tui
        .check_tab_data
        .last_rendered_check_ids
        .get(tui.check_tab_data.current_highlight_index)
    else {
        return;
    };

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
    }

    handle_movement(tui, &key);
    handle_selects(tui, &key).await;
}

async fn handle_selects(tui: &mut super::Tui<'_>, key: &KeyEvent) {
    let Some(current_check_selected) = tui
        .check_tab_data
        .last_rendered_check_ids
        .get(tui.check_tab_data.current_highlight_index)
    else {
        return;
    };

    if let Some(open_state) = tui
        .check_tab_data
        .open_checks
        .get_mut(&current_check_selected)
        && let CheckHighlight::Controls(control) = &tui.check_tab_data.current_highlight_state
    {
        if *control == CheckControls::RunOnce
            && let KeyCode::Char(' ') | KeyCode::Enter = key.code
        {
            let Ok(lock) = tui.checks.read() else {
                return;
            };

            let Some(host) = lock.checks.get(&current_check_selected.0) else {
                return;
            };
            let Some(check) = host.get(&current_check_selected.1) else {
                return;
            };

            let _ = check
                .1
                .message_sender
                .send(OutboundMessage::TriggerNow)
                .await;
        }
        if *control == CheckControls::StartStop
            && let KeyCode::Char(' ') | KeyCode::Enter = key.code
        {
            let Ok(lock) = tui.checks.read() else {
                return;
            };

            let Some(host) = lock.checks.get(&current_check_selected.0) else {
                return;
            };
            let Some(check) = host.get(&current_check_selected.1) else {
                return;
            };

            if check.1.started.load(Ordering::Acquire) {
                let _ = check.1.message_sender.send(OutboundMessage::Stop).await;
            } else {
                let _ = check.1.message_sender.send(OutboundMessage::Start).await;
            }
        }
        if *control == CheckControls::ShowHideAllResults
            && let KeyCode::Char(' ') | KeyCode::Enter = key.code
        {
            open_state.viewing_all = !open_state.viewing_all;
        }
    }
}

fn handle_movement(tui: &mut super::Tui<'_>, key: &KeyEvent) {
    let Some(current_check_selected) = tui
        .check_tab_data
        .last_rendered_check_ids
        .get(tui.check_tab_data.current_highlight_index)
    else {
        return;
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
                        .get(current_check_selected)
                        .map(|l| l.len())
                        .unwrap_or_default();

                    tui.check_tab_data.current_highlight_state =
                        CheckHighlight::AllResults(logs_length);
                } else {
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

                    tui.check_tab_data.current_highlight_state =
                        CheckHighlight::BadResults(logs_length);
                }
            } else {
                tui.check_tab_data.current_highlight_state = CheckHighlight::Check;
            }
            tui.check_tab_data.current_highlight_index -= 1;
            return;
        }

        if is_generic_down(&key)
            && let CheckHighlight::Check = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state =
                CheckHighlight::Controls(CheckControls::RunOnce);
            return;
        }

        if is_generic_up(&key)
            && let CheckHighlight::Controls(_) = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::Check;
            return;
        }

        if is_generic_down(&key)
            && let CheckHighlight::Controls(_) = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::RecentResults(0);
            return;
        }

        if is_generic_left(&key)
            && let CheckHighlight::Controls(control) = &tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::Controls(control.left());
            return;
        }

        if is_generic_right(&key)
            && let CheckHighlight::Controls(control) = &tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::Controls(control.right());
            return;
        }

        if is_generic_up(&key)
            && let CheckHighlight::RecentResults(0) = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state =
                CheckHighlight::Controls(CheckControls::RunOnce);
            return;
        }

        if is_generic_up(&key)
            && let CheckHighlight::RecentResults(i) = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::RecentResults(i - 1);
            return;
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
            return;
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
        }

        if is_generic_up(&key)
            && let CheckHighlight::BadResults(i) = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::BadResults(i - 1);
            return;
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
            return;
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

            return;
        }

        if is_generic_up(&key)
            && let CheckHighlight::AllResults(i) = tui.check_tab_data.current_highlight_state
        {
            tui.check_tab_data.current_highlight_state = CheckHighlight::AllResults(i - 1);
            return;
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
            return;
        }
    } else {
        if is_generic_down(&key) {
            tui.check_tab_data.current_highlight_index =
                (1 + tui.check_tab_data.current_highlight_index)
                    .clamp(0, tui.check_tab_data.last_rendered_check_ids.len() - 1);
            return;
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
                        .get(current_check_selected)
                        .map(|l| l.len())
                        .unwrap_or_default();

                    tui.check_tab_data.current_highlight_state =
                        CheckHighlight::AllResults(logs_length);
                } else {
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

                    tui.check_tab_data.current_highlight_state =
                        CheckHighlight::BadResults(logs_length);
                }
            } else {
                tui.check_tab_data.current_highlight_state = CheckHighlight::Check;
            }
            tui.check_tab_data.current_highlight_index -= 1;
            return;
        }
    }
}
