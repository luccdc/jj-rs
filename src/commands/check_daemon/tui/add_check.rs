#[cfg(unix)]
use std::io::PipeWriter;
use std::{net::Ipv4Addr, sync::Arc};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Margin, Rect},
    style::{Color, Style, Styled, Stylize},
    text::Line,
    widgets::{Block, Clear, Tabs},
};
use serde_json::Map;
use tokio::sync::mpsc;

use crate::commands::check_daemon::DaemonConfig;

use super::{
    CheckId, Tui,
    components::text_input::{ErrorTextInput, ErrorTextInputState, TextInput, TextInputState},
    is_generic_down, is_generic_left, is_generic_right, is_generic_up,
};

#[derive(PartialEq, Eq)]
enum AddCheckSelectState {
    SelectBox(usize),
}

impl Default for AddCheckSelectState {
    fn default() -> Self {
        Self::SelectBox(0)
    }
}

type ETIS<T> = ErrorTextInputState<T, Box<dyn for<'a> Fn(&'a str) -> Result<T, String>>>;

enum AddCheckWizardState {
    DnsStage1(usize, ETIS<Ipv4Addr>, TextInputState),
    SshStage1(usize, ETIS<Ipv4Addr>, TextInputState),
    HttpStage1(usize, ETIS<Ipv4Addr>, ETIS<u16>, TextInputState),
    Generalize(
        usize,
        usize,
        &'static str,
        Vec<(String, ETIS<serde_json::Value>)>,
    ),
    Finalize(
        usize,
        usize,
        crate::checks::CheckTypes,
        TextInputState,
        TextInputState,
    ),
}

#[derive(Default)]
pub struct AddCheckState {
    select_state: AddCheckSelectState,
    wizard_state: Option<AddCheckWizardState>,
}

pub fn render(tui: &mut Tui<'_>, frame: &mut Frame, area: Rect, selected: bool) {
    let [tab_box, _] = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).areas(area);

    frame.render_widget(
        Block::bordered()
            .title("Check type")
            .set_style(if selected {
                Style::new().fg(Color::Yellow)
            } else {
                Style::new()
            }),
        tab_box,
    );

    let AddCheckSelectState::SelectBox(i) = tui.add_check_tab.select_state;

    frame.render_widget(
        Tabs::new(crate::checks::CheckTypes::check_names())
            .style(Style::default().white())
            .highlight_style(if selected {
                Style::default().bg(Color::Yellow)
            } else {
                Style::default().fg(Color::Yellow)
            })
            .select(Some(i)),
        tab_box.inner(Margin {
            vertical: 1,
            horizontal: 1,
        }),
    );

    if tui.add_check_tab.wizard_state.is_some() {
        frame.render_widget(Clear, area.clone());
    }

    match &mut tui.add_check_tab.wizard_state {
        None => {}
        Some(AddCheckWizardState::DnsStage1(s, host, name)) => {
            frame.render_widget(Block::bordered().title("DNS Check Setup Wizard"), area);

            let [submit, host_block, query_block] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .areas(area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }));

            let submit_style = if *s == 0 && selected {
                Style::new().yellow()
            } else {
                Style::new()
            };

            frame.render_widget(
                if tui.check_setup_task.is_some() {
                    Line::raw("Loading... Cancel?")
                } else {
                    Line::raw("Submit")
                }
                .style(submit_style),
                submit.inner(Margin {
                    vertical: 0,
                    horizontal: 1,
                }),
            );

            host.set_selected(*s == 1 && selected);
            frame.render_stateful_widget(
                ErrorTextInput::default()
                    .label(Some("Host/IP:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                host_block,
                host,
            );
            if *s == 1 && selected {
                ErrorTextInput::default().set_cursor_position(host_block, frame, host);
            }

            name.set_selected(*s == 2 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("URI:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                query_block,
                name,
            );
            if *s == 2 && selected {
                TextInput::default().set_cursor_position(query_block, frame, name);
            }
        }
        Some(AddCheckWizardState::HttpStage1(s, host, port, uri)) => {
            frame.render_widget(Block::bordered().title("HTTP Check Setup Wizard"), area);

            let [host_block, port_block, uri_block, submit] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .areas(area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }));

            let submit_style = if *s == 0 && selected {
                Style::new().yellow()
            } else {
                Style::new()
            };

            frame.render_widget(
                if tui.check_setup_task.is_some() {
                    Line::raw("Loading... Cancel?")
                } else {
                    Line::raw("Submit")
                }
                .style(submit_style),
                submit.inner(Margin {
                    vertical: 0,
                    horizontal: 1,
                }),
            );

            host.set_selected(*s == 1 && selected);
            frame.render_stateful_widget(
                ErrorTextInput::default()
                    .label(Some("Host/IP:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                host_block,
                host,
            );
            if *s == 1 && selected {
                ErrorTextInput::default().set_cursor_position(host_block, frame, host);
            }

            port.set_selected(*s == 2 && selected);
            frame.render_stateful_widget(
                ErrorTextInput::default()
                    .label(Some("Port:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                port_block,
                port,
            );
            if *s == 2 && selected {
                ErrorTextInput::default().set_cursor_position(port_block, frame, port);
            }

            uri.set_selected(*s == 3 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("URI:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                uri_block,
                uri,
            );
            if *s == 3 && selected {
                TextInput::default().set_cursor_position(uri_block, frame, uri);
            }
        }
        Some(AddCheckWizardState::SshStage1(s, host, username)) => {
            frame.render_widget(Block::bordered().title("SSH Check Setup Wizard"), area);

            let [submit, host_block, user_block] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .areas(area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }));

            let submit_style = if *s == 0 && selected {
                Style::new().yellow()
            } else {
                Style::new()
            };

            frame.render_widget(
                if tui.check_setup_task.is_some() {
                    Line::raw("Loading... Cancel?")
                } else {
                    Line::raw("Submit")
                }
                .style(submit_style),
                submit.inner(Margin {
                    vertical: 0,
                    horizontal: 1,
                }),
            );

            host.set_selected(*s == 1 && selected);
            frame.render_stateful_widget(
                ErrorTextInput::default()
                    .label(Some("Host/IP:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                host_block,
                host,
            );
            if *s == 1 && selected {
                ErrorTextInput::default().set_cursor_position(host_block, frame, host);
            }

            username.set_selected(*s == 2 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("URI:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                user_block,
                username,
            );
            if *s == 2 && selected {
                TextInput::default().set_cursor_position(user_block, frame, username);
            }
        }
        Some(AddCheckWizardState::Generalize(s, t, _, inputs)) => {
            frame.render_widget(Block::bordered().title("Confirm check settings"), area);

            let mut working_area = area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            });

            if *s == 0 {
                let mut tabs_area = working_area.clone();
                tabs_area.height = 1;
                tabs_area.x += 1;

                frame.render_widget(
                    Tabs::new(vec!["Next", "Cancel"])
                        .style(Style::default().white())
                        .highlight_style(if *s == 0 && selected {
                            Style::new().bg(Color::Yellow)
                        } else {
                            Style::new().fg(Color::Yellow)
                        })
                        .select(*t),
                    tabs_area,
                );

                working_area.height = working_area.height.saturating_sub(1);
                working_area.y += 1;
            }

            let mut inputs = inputs[s.saturating_sub(1)..].iter_mut().enumerate();
            while working_area.height > 0
                && let Some((i, (key, input_state))) = inputs.next()
            {
                let mut editor_area = working_area.clone();
                editor_area.height = 3;

                input_state.set_selected(i == 0 && selected && *s > 0);
                frame.render_stateful_widget(
                    ErrorTextInput::default()
                        .label(Some(key))
                        .selected_style(Some(Style::new().fg(Color::Yellow))),
                    editor_area,
                    input_state,
                );

                if i == 0 && selected && *s > 0 {
                    ErrorTextInput::default().set_cursor_position(editor_area, frame, input_state);
                }

                working_area.height = working_area.height.saturating_sub(3);
                working_area.y += 3;
            }
        }
        Some(AddCheckWizardState::Finalize(s, t, _, host, check_name)) => {
            frame.render_widget(Block::bordered().title("Finalize Check Setup"), area);

            let [submit, host_block, query_block] = Layout::vertical([
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .areas(area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }));

            frame.render_widget(
                Tabs::new(vec!["Submit", "Cancel"])
                    .style(Style::default().white())
                    .highlight_style(if *s == 0 && selected {
                        Style::new().bg(Color::Yellow)
                    } else {
                        Style::new().fg(Color::Yellow)
                    })
                    .select(*t),
                submit,
            );

            host.set_selected(*s == 1 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("Host name:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                host_block,
                host,
            );
            if *s == 1 && selected {
                TextInput::default().set_cursor_position(host_block, frame, host);
            }

            check_name.set_selected(*s == 2 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("Check name:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                query_block,
                check_name,
            );
            if *s == 2 && selected {
                TextInput::default().set_cursor_position(query_block, frame, check_name);
            }
        }
    }
}

pub async fn handle_keypress<'scope, 'env: 'scope>(
    tui: &mut Tui<'env>,
    key: KeyEvent,
    #[cfg(unix)] log_writer: &PipeWriter,
    #[cfg(windows)] log_writer: &tokio::sync::mpsc::Sender<super::logs::LogEvent>,
    prompt_writer: &mpsc::Sender<(CheckId, String)>,
    checks_scope: &'scope std::thread::Scope<'scope, 'env>,
    send_shutdown: &tokio::sync::broadcast::Sender<()>,
) -> bool {
    let KeyEventKind::Press = key.kind else {
        return false;
    };

    let AddCheckSelectState::SelectBox(i) = tui.add_check_tab.select_state;

    if handle_wizard(
        tui,
        &key,
        log_writer,
        prompt_writer,
        checks_scope,
        send_shutdown,
    ) {
        return true;
    }

    let ip_parser = Box::new(|s: &str| s.parse::<Ipv4Addr>().map_err(|e| format!("{e}")));
    let port_parser = Box::new(|s: &str| s.parse::<u16>().map_err(|e| format!("{e}")));

    if let KeyCode::Char(' ') | KeyCode::Enter = key.code {
        tui.add_check_tab.wizard_state = match crate::checks::CheckTypes::check_names().get(i) {
            Some(&"SSH") => Some(AddCheckWizardState::SshStage1(
                0,
                ErrorTextInputState::new(ip_parser.clone() as Box<_>)
                    .set_input("127.0.0.1".to_string()),
                TextInputState::default().set_input("root".to_string()),
            )),
            Some(&"DNS") => Some(AddCheckWizardState::DnsStage1(
                0,
                ErrorTextInputState::new(ip_parser.clone() as Box<_>)
                    .set_input("127.0.0.1".to_string()),
                TextInputState::default().set_input("google.com".to_string()),
            )),
            Some(&"HTTP") => Some(AddCheckWizardState::HttpStage1(
                0,
                ErrorTextInputState::new(ip_parser.clone() as Box<_>)
                    .set_input("127.0.0.1".to_string()),
                ErrorTextInputState::new(port_parser.clone() as Box<_>).set_input("80".to_string()),
                TextInputState::default().set_input("/".to_string()),
            )),
            _ => None,
        };
        tui.buffer.clear();
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

    false
}

fn handle_wizard<'scope, 'env: 'scope>(
    tui: &mut Tui<'env>,
    key: &KeyEvent,
    #[cfg(unix)] log_writer: &PipeWriter,
    #[cfg(windows)] log_writer: &tokio::sync::mpsc::Sender<super::logs::LogEvent>,
    prompt_writer: &mpsc::Sender<(CheckId, String)>,
    checks_scope: &'scope std::thread::Scope<'scope, 'env>,
    send_shutdown: &tokio::sync::broadcast::Sender<()>,
) -> bool {
    match &mut tui.add_check_tab.wizard_state {
        None => false,
        Some(AddCheckWizardState::DnsStage1(s, host, name)) => {
            if let KeyCode::Char('n') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                *s = (*s + 1).min(2);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Down = key.code {
                *s = (*s + 1).min(2);
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::Char('p') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                if *s == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *s = s.saturating_sub(1);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Up = key.code {
                if *s == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *s = s.saturating_sub(1);
                tui.buffer.clear();
                return true;
            }

            if *s == 1 {
                if host.handle_keybind(*key) {
                    tui.buffer.clear();
                    return true;
                }
            }

            if *s == 2 {
                if name.handle_keybind(*key) {
                    tui.buffer.clear();
                    return true;
                }
            }

            if *s == 0 {
                if let KeyCode::Char(' ') | KeyCode::Enter = key.code {
                    let Ok(addr) = host.parse() else {
                        tui.buffer.clear();
                        return true;
                    };

                    let Ok(serde_json::Value::Object(check_type)) =
                        serde_json::to_value(&crate::checks::dns::Dns {
                            host: addr,
                            domain: name.input().to_string(),
                            ..Default::default()
                        })
                    else {
                        tui.buffer.clear();
                        return true;
                    };

                    let check_fields = (&check_type)
                        .into_iter()
                        .map(|(key, value)| {
                            let check_type = check_type.clone();
                            let key = key.to_owned();
                            let is_str = value.is_string();
                            (
                                key.clone(),
                                ErrorTextInputState::new(Box::new(
                                    move |inp: &str| -> Result<serde_json::Value, String> {
                                        let parsed: serde_json::Value = if is_str {
                                            serde_json::Value::String(inp.to_owned())
                                        } else {
                                            serde_json::from_str(&inp)
                                                .map_err(|e| format!("{e}"))?
                                        };

                                        let mut check_type = check_type.clone();
                                        check_type.insert(key.clone(), parsed.clone());

                                        serde_json::from_value::<crate::checks::dns::Dns>(
                                            serde_json::Value::Object(check_type),
                                        )
                                        .map(|_| parsed)
                                        .map_err(|e| format!("{e}"))
                                    },
                                )
                                    as Box<
                                        dyn for<'a> Fn(
                                            &'a str,
                                        )
                                            -> Result<serde_json::Value, String>,
                                    >)
                                .set_input(
                                    if let serde_json::Value::String(v) = value {
                                        v.clone()
                                    } else {
                                        serde_json::to_string(&value).unwrap_or_default()
                                    },
                                ),
                            )
                        })
                        .collect();

                    tui.add_check_tab.wizard_state =
                        Some(AddCheckWizardState::Generalize(0, 0, "dns", check_fields));

                    tui.buffer.clear();
                    return true;
                }
            }

            if is_generic_up(key) {
                tui.buffer.clear();
                return true;
            }
            if is_generic_down(key) {
                tui.buffer.clear();
                return true;
            }

            tui.buffer.clear();
            false
        }
        Some(AddCheckWizardState::HttpStage1(s, host, port, uri)) => {
            if let KeyCode::Char('n') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                *s = (*s + 1).min(2);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Down = key.code {
                *s = (*s + 1).min(2);
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::Char('p') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                if *s == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *s = s.saturating_sub(1);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Up = key.code {
                if *s == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *s = s.saturating_sub(1);
                tui.buffer.clear();
                return true;
            }

            if *s == 1 {
                if host.handle_keybind(*key) {
                    tui.buffer.clear();
                    return true;
                }
            }

            if *s == 2 {
                if port.handle_keybind(*key) {
                    tui.buffer.clear();
                    return true;
                }
            }

            if *s == 3 {
                if uri.handle_keybind(*key) {
                    tui.buffer.clear();
                    return true;
                }
            }

            if *s == 0 {
                if let KeyCode::Char(' ') | KeyCode::Enter = key.code {
                    let Ok(host) = host.parse() else {
                        tui.buffer.clear();
                        return true;
                    };
                    let Ok(port) = port.parse() else {
                        tui.buffer.clear();
                        return true;
                    };

                    let Ok(serde_json::Value::Object(check_type)) =
                        serde_json::to_value(&crate::checks::http::HttpTroubleshooter {
                            host,
                            port,
                            uri: uri.input().to_owned(),
                            ..Default::default()
                        })
                    else {
                        tui.buffer.clear();
                        return true;
                    };

                    let check_fields = (&check_type)
                        .into_iter()
                        .map(|(key, value)| {
                            let check_type = check_type.clone();
                            let key = key.to_owned();
                            let is_str = value.is_string();
                            (
                                key.clone(),
                                ErrorTextInputState::new(Box::new(
                                    move |inp: &str| -> Result<serde_json::Value, String> {
                                        let parsed: serde_json::Value = if is_str {
                                            serde_json::Value::String(inp.to_owned())
                                        } else {
                                            serde_json::from_str(&inp)
                                                .map_err(|e| format!("{e}"))?
                                        };

                                        let mut check_type = check_type.clone();
                                        check_type.insert(key.clone(), parsed.clone());

                                        serde_json::from_value::<
                                            crate::checks::http::HttpTroubleshooter,
                                        >(
                                            serde_json::Value::Object(check_type)
                                        )
                                        .map(|_| parsed)
                                        .map_err(|e| format!("{e}"))
                                    },
                                )
                                    as Box<
                                        dyn for<'a> Fn(
                                            &'a str,
                                        )
                                            -> Result<serde_json::Value, String>,
                                    >)
                                .set_input(
                                    if let serde_json::Value::String(v) = value {
                                        v.clone()
                                    } else {
                                        serde_json::to_string(&value).unwrap_or_default()
                                    },
                                ),
                            )
                        })
                        .collect();

                    tui.add_check_tab.wizard_state =
                        Some(AddCheckWizardState::Generalize(0, 0, "http", check_fields));

                    tui.buffer.clear();
                    return true;
                }
            }

            if is_generic_up(key) {
                tui.buffer.clear();
                return true;
            }
            if is_generic_down(key) {
                tui.buffer.clear();
                return true;
            }

            tui.buffer.clear();
            false
        }
        Some(AddCheckWizardState::SshStage1(s, host, user)) => {
            if let KeyCode::Char('n') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                *s = (*s + 1).min(2);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Down = key.code {
                *s = (*s + 1).min(2);
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::Char('p') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                if *s == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *s = s.saturating_sub(1);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Up = key.code {
                if *s == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *s = s.saturating_sub(1);
                tui.buffer.clear();
                return true;
            }

            if *s == 1 {
                if host.handle_keybind(*key) {
                    tui.buffer.clear();
                    return true;
                }
            }

            if *s == 2 {
                if user.handle_keybind(*key) {
                    tui.buffer.clear();
                    return true;
                }
            }

            if *s == 0 {
                if let KeyCode::Char(' ') | KeyCode::Enter = key.code {
                    let Ok(host) = host.parse() else {
                        tui.buffer.clear();
                        return true;
                    };

                    let Ok(serde_json::Value::Object(check_type)) =
                        serde_json::to_value(&crate::checks::ssh::SshTroubleshooter {
                            host,
                            user: user.input().to_owned(),
                            ..Default::default()
                        })
                    else {
                        tui.buffer.clear();
                        return true;
                    };

                    let check_fields = (&check_type)
                        .into_iter()
                        .map(|(key, value)| {
                            let check_type = check_type.clone();
                            let key = key.to_owned();
                            let is_str = value.is_string();
                            (
                                key.clone(),
                                ErrorTextInputState::new(Box::new(
                                    move |inp: &str| -> Result<serde_json::Value, String> {
                                        let parsed: serde_json::Value = if is_str {
                                            serde_json::Value::String(inp.to_owned())
                                        } else {
                                            serde_json::from_str(&inp)
                                                .map_err(|e| format!("{e}"))?
                                        };

                                        let mut check_type = check_type.clone();
                                        check_type.insert(key.clone(), parsed.clone());

                                        serde_json::from_value::<
                                            crate::checks::ssh::SshTroubleshooter,
                                        >(
                                            serde_json::Value::Object(check_type)
                                        )
                                        .map(|_| parsed)
                                        .map_err(|e| format!("{e}"))
                                    },
                                )
                                    as Box<
                                        dyn for<'a> Fn(
                                            &'a str,
                                        )
                                            -> Result<serde_json::Value, String>,
                                    >)
                                .set_input(
                                    if let serde_json::Value::String(v) = value {
                                        v.clone()
                                    } else {
                                        serde_json::to_string(&value).unwrap_or_default()
                                    },
                                ),
                            )
                        })
                        .collect();

                    tui.add_check_tab.wizard_state =
                        Some(AddCheckWizardState::Generalize(0, 0, "ssh", check_fields));

                    tui.buffer.clear();
                    return true;
                }
            }

            if is_generic_up(key) {
                tui.buffer.clear();
                return true;
            }
            if is_generic_down(key) {
                tui.buffer.clear();
                return true;
            }

            tui.buffer.clear();
            false
        }
        Some(AddCheckWizardState::Generalize(s, t, check_type, fields)) => {
            if let KeyCode::Char('n') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                *s = (*s + 1).min(fields.len());
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Down = key.code {
                *s = (*s + 1).min(fields.len());
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::Char('p') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                if *s == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *s = s.saturating_sub(1);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Up = key.code {
                if *s == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *s = s.saturating_sub(1);
                tui.buffer.clear();
                return true;
            }

            if *s == 0 {
                if is_generic_left(key) {
                    *t = t.saturating_sub(1);
                } else if is_generic_right(key) {
                    *t = t.saturating_add(1).min(1);
                }

                if *t == 0
                    && let KeyCode::Char(' ') | KeyCode::Enter = key.code
                {
                    let Ok(v) = fields
                        .iter()
                        .map(|(key, value)| value.parse().map(|v| (key.clone(), v)))
                        .collect::<Result<Map<_, _>, _>>()
                    else {
                        eprintln!("Could not finalize check configuration (serialization 1)");
                        tui.buffer.clear();
                        return true;
                    };

                    let json = serde_json::json!({
                        *check_type: serde_json::Value::Object(v)
                    });

                    let Ok(parsed) = serde_json::from_value(json) else {
                        eprintln!("Could not finalize check configuration (serialization 2)");
                        tui.buffer.clear();
                        return true;
                    };

                    tui.add_check_tab.wizard_state = Some(AddCheckWizardState::Finalize(
                        0,
                        0,
                        parsed,
                        TextInputState::default(),
                        TextInputState::default(),
                    ));
                } else if *t == 1
                    && let KeyCode::Char(' ') | KeyCode::Enter = key.code
                {
                    tui.add_check_tab.wizard_state = None;
                }

                tui.buffer.clear();
                return true;
            } else if let Some((_, fields)) = fields.get_mut(*s - 1) {
                if fields.handle_keybind(*key) {
                    tui.buffer.clear();
                    return true;
                }
            }

            if is_generic_up(key) {
                tui.buffer.clear();
                return true;
            }
            if is_generic_down(key) {
                tui.buffer.clear();
                return true;
            }

            tui.buffer.clear();
            false
        }
        Some(AddCheckWizardState::Finalize(s, t, check, host, name)) => {
            if let KeyCode::Char('n') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                *s = (*s + 1).min(2);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Down = key.code {
                *s = (*s + 1).min(2);
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::Char('p') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                if *s == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *s = s.saturating_sub(1);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Up = key.code {
                if *s == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *s = s.saturating_sub(1);
                tui.buffer.clear();
                return true;
            }

            if *s == 1 {
                if host.handle_keybind(*key) {
                    tui.buffer.clear();
                    return true;
                }
            }

            if *s == 2 {
                if name.handle_keybind(*key) {
                    tui.buffer.clear();
                    return true;
                }
            }

            if *s == 0 {
                if is_generic_left(key) {
                    *t = t.saturating_sub(1);
                } else if is_generic_right(key) {
                    *t = t.saturating_add(1).min(1);
                }

                if *t == 0
                    && let KeyCode::Char(' ') | KeyCode::Enter = key.code
                {
                    #[cfg(unix)]
                    let Ok(log_writer) = log_writer.try_clone() else {
                        eprintln!("Could not clone log writer!");
                        return true;
                    };

                    if let Err(e) = super::super::check_thread::register_check(
                        tui.checks,
                        (
                            CheckId(Arc::from(host.input()), Arc::from(name.input())),
                            check.clone(),
                        ),
                        checks_scope,
                        prompt_writer.clone(),
                        #[cfg(unix)]
                        log_writer,
                        #[cfg(windows)]
                        log_writer.clone(),
                        send_shutdown.subscribe(),
                        false,
                    ) {
                        eprintln!("Could not register new check: {e}");
                    }

                    let Some(path) = tui.config_file_path.as_ref() else {
                        tui.buffer.clear();
                        return true;
                    };
                    let Ok(mut config_parsed) = std::fs::read(path)
                        .map_err(|_| ())
                        .and_then(|c| toml::from_slice::<DaemonConfig>(&c).map_err(|_| ()))
                    else {
                        eprintln!("Could load old config to save new config");
                        tui.buffer.clear();
                        return true;
                    };

                    let host = config_parsed.checks.entry(host.input().into());
                    let host = host.or_default();
                    host.insert(name.input().into(), check.clone());

                    if let Err(e) = toml::to_string_pretty(&config_parsed)
                        .map_err(|e| format!("{e}"))
                        .and_then(|c| std::fs::write(path, c).map_err(|e| format!("{e}")))
                    {
                        eprintln!("Could not save configuration: {e}");
                    }

                    tui.add_check_tab.wizard_state = None;
                    tui.current_tab = super::Tab::Checks;
                } else if *t == 1
                    && let KeyCode::Char(' ') | KeyCode::Enter = key.code
                {
                    tui.add_check_tab.wizard_state = None;
                }

                tui.buffer.clear();
                return true;
            }

            false
        }
    }
}

fn handle_movement(tui: &mut Tui<'_>, key: &KeyEvent) -> bool {
    let AddCheckSelectState::SelectBox(i) = tui.add_check_tab.select_state;

    if is_generic_up(&key) {
        tui.current_selection = super::CurrentSelection::Tabs;
        tui.buffer.clear();
        return true;
    }

    if is_generic_left(&key) {
        tui.add_check_tab.select_state = AddCheckSelectState::SelectBox(i.saturating_sub(1));
        tui.buffer.clear();
        return true;
    }

    if is_generic_right(&key) {
        tui.add_check_tab.select_state = AddCheckSelectState::SelectBox(
            i.saturating_add(1)
                .min(crate::checks::CheckTypes::check_names().len() - 1),
        );
        tui.buffer.clear();
        return true;
    }

    false
}
