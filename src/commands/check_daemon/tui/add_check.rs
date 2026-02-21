#[cfg(unix)]
use std::io::PipeWriter;
use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use chrono::Utc;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Margin, Rect},
    style::{Color, Style, Styled, Stylize},
    text::Line,
    widgets::{Block, Clear, Paragraph, Scrollbar, ScrollbarState, Tabs},
};
use serde_json::Map;
use sha2::Digest;
use tokio::{io::AsyncWriteExt, sync::mpsc};

use crate::{checks::CheckValue, commands::check_daemon::DaemonConfig};

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

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
enum ChildrenState {
    Loaded,
    Loading,
    NotLoaded,
}

#[derive(Clone, Ord, Eq)]
struct RemoteFileListing {
    name: String,
    selected: bool,
    is_dir: bool,
    children_state: ChildrenState,
    children: Option<Vec<RemoteFileListing>>,
    open: bool,
}

impl PartialEq for RemoteFileListing {
    fn eq(&self, other: &Self) -> bool {
        self.name.eq(&other.name)
    }
}

impl PartialOrd for RemoteFileListing {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let mut self_parts = self.name.split('/');
        let mut other_parts = other.name.split('/');

        loop {
            let self_part = self_parts.next();
            let other_part = other_parts.next();

            match (self_part, other_part) {
                (None, None) => break Some(std::cmp::Ordering::Equal),
                (Some(_), None) => break Some(std::cmp::Ordering::Greater),
                (None, Some(_)) => break Some(std::cmp::Ordering::Less),
                (Some(left), Some(right)) if left != right => break Some(left.cmp(right)),
                (_, _) => {}
            }
        }
    }
}

enum AddCheckWizardState {
    DnsStage1 {
        selection: usize,
        host: ETIS<Ipv4Addr>,
        query: TextInputState,
    },
    FtpStage1 {
        selection: usize,
        host: ETIS<Ipv4Addr>,
        username: TextInputState,
        password: TextInputState,
        root_dir: TextInputState,
        auto_setup: bool,
        connect_error: Option<String>,
    },
    FtpStage2 {
        selection: usize,
        vertical_scroll: usize,
        horizontal_scroll: usize,
        vertical_scroll_state: ScrollbarState,
        horizontal_scroll_state: ScrollbarState,
        err_message: Option<String>,
        tab_selection: usize,
        clear_password: bool,
        host: Ipv4Addr,
        username: String,
        password: String,
        filter_state: TextInputState,
        client_session: Arc<Mutex<ftp::FtpStream>>,
        file_listings: RemoteFileListing,
    },
    HttpStage1 {
        selection: usize,
        host: ETIS<Ipv4Addr>,
        port: ETIS<u16>,
        uri: TextInputState,
        auto_setup: bool,
        connect_error: Option<String>,
    },
    SshStage1 {
        selection: usize,
        host: ETIS<Ipv4Addr>,
        username: TextInputState,
    },
    Generalize {
        row_selection: usize,
        tab_selection: usize,
        check_type: &'static str,
        check_fields: Vec<(String, ETIS<serde_json::Value>)>,
    },
    Finalize {
        selection: usize,
        tab_selection: usize,
        check: crate::checks::CheckTypes,
        host: TextInputState,
        service: TextInputState,
    },
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
        Some(AddCheckWizardState::DnsStage1 {
            selection,
            host,
            query,
        }) => {
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

            let submit_style = if *selection == 0 && selected {
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

            host.set_selected(*selection == 1 && selected);
            frame.render_stateful_widget(
                ErrorTextInput::default()
                    .label(Some("Host/IP:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                host_block,
                host,
            );
            if *selection == 1 && selected {
                ErrorTextInput::default().set_cursor_position(host_block, frame, host);
            }

            query.set_selected(*selection == 2 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("URI:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                query_block,
                query,
            );
            if *selection == 2 && selected {
                TextInput::default().set_cursor_position(query_block, frame, query);
            }
        }
        Some(AddCheckWizardState::FtpStage1 {
            connect_error,
            selection,
            host,
            username,
            password,
            root_dir,
            auto_setup,
        }) => {
            frame.render_widget(Block::bordered().title("FTP Check Setup Wizard"), area);

            let [
                error_block,
                submit,
                host_block,
                user_block,
                pass_block,
                dir_block,
                auto_block,
            ] = Layout::vertical([
                Constraint::Length(if connect_error.is_some() { 3 } else { 0 }),
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .areas(area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }));

            if let Some(err) = connect_error {
                frame.render_widget(
                    Block::bordered()
                        .title("Connection error!")
                        .title_style(Style::new().red()),
                    error_block,
                );
                frame.render_widget(
                    Line::raw(err.clone()),
                    error_block.inner(Margin {
                        vertical: 1,
                        horizontal: 1,
                    }),
                );
            }

            frame.render_widget(
                if tui.check_setup_task.is_some() {
                    Line::raw("Loading... Cancel?")
                } else {
                    Line::raw("Submit")
                }
                .style(if *selection == 0 && selected {
                    Style::new().yellow()
                } else {
                    Style::new()
                }),
                submit.inner(Margin {
                    vertical: 0,
                    horizontal: 1,
                }),
            );

            host.set_selected(*selection == 1 && selected);
            frame.render_stateful_widget(
                ErrorTextInput::default()
                    .label(Some("Host/IP:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                host_block,
                host,
            );
            if *selection == 1 && selected {
                ErrorTextInput::default().set_cursor_position(host_block, frame, host);
            }

            username.set_selected(*selection == 2 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("Username:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                user_block,
                username,
            );
            if *selection == 2 && selected {
                TextInput::default().set_cursor_position(user_block, frame, username);
            }

            password.set_selected(*selection == 3 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("Password:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                pass_block,
                password,
            );
            if *selection == 3 && selected {
                TextInput::default().set_cursor_position(pass_block, frame, password);
            }

            root_dir.set_selected(*selection == 4 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("Browse root:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                dir_block,
                root_dir,
            );
            if *selection == 4 && selected {
                TextInput::default().set_cursor_position(dir_block, frame, root_dir);
            }

            frame.render_widget(
                Line::raw(&format!(
                    "[{}] Auto setup",
                    if *auto_setup { "X" } else { " " }
                ))
                .style(if *selection == 5 && selected {
                    Style::new().fg(Color::Yellow)
                } else {
                    Style::new()
                }),
                auto_block,
            );
        }
        Some(AddCheckWizardState::FtpStage2 {
            selection,
            vertical_scroll,
            horizontal_scroll,
            vertical_scroll_state,
            horizontal_scroll_state,
            err_message,
            tab_selection,
            clear_password,
            file_listings,
            filter_state,
            ..
        }) => {
            frame.render_widget(Block::bordered().title("FTP Check Setup Wizard"), area);

            let [err_block, submit, password_setting, filter_block, files] = Layout::vertical([
                Constraint::Length(if err_message.is_some() { 3 } else { 0 }),
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Fill(1),
            ])
            .areas(area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }));

            if let Some(err) = err_message {
                frame.render_widget(
                    Block::bordered().title("").title_style(Style::new().red()),
                    err_block,
                );
                frame.render_widget(
                    Line::raw(err.clone()),
                    err_block.inner(Margin {
                        vertical: 1,
                        horizontal: 1,
                    }),
                );
            }

            frame.render_widget(
                Tabs::new(vec!["Next", "Cancel"])
                    .style(Style::default().white())
                    .highlight_style(if *selection == 0 && selected {
                        Style::new().bg(Color::Yellow)
                    } else {
                        Style::new().fg(Color::Yellow)
                    })
                    .select(*tab_selection),
                submit,
            );

            frame.render_widget(
                Line::raw(&format!(
                    "[{}] Clear password when saving check",
                    if *clear_password { "X" } else { " " }
                ))
                .style(if *selection == 1 && selected {
                    Style::new().fg(Color::Yellow)
                } else {
                    Style::new()
                }),
                password_setting,
            );

            filter_state.set_selected(*selection > 1 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("File filter:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                filter_block,
                filter_state,
            );
            if *selection > 1 && selected {
                TextInput::default().set_cursor_position(filter_block, frame, filter_state);
            }

            frame.render_widget(Block::bordered().title("File listing"), files);

            let mut lines = vec![];
            let mut index = 0;

            fn render(
                filter: &str,
                selection: usize,
                lines: &mut Vec<Line<'static>>,
                index: &mut usize,
                listing: &RemoteFileListing,
            ) {
                if listing.name.contains(filter) {
                    lines.push(
                        Line::default()
                            .spans(vec![
                                format!(
                                    "{}{}{} ",
                                    if listing.is_dir { "d" } else { "-" },
                                    match (listing.is_dir, listing.children_state) {
                                        (true, ChildrenState::Loaded) => {
                                            "+"
                                        }
                                        (true, ChildrenState::Loading) => {
                                            "."
                                        }
                                        (true, ChildrenState::NotLoaded) => {
                                            "-"
                                        }
                                        _ => {
                                            " "
                                        }
                                    },
                                    match (listing.is_dir, listing.open) {
                                        (true, true) => {
                                            "-"
                                        }
                                        (true, false) => {
                                            "+"
                                        }
                                        _ => {
                                            " "
                                        }
                                    }
                                ),
                                listing.name.clone(),
                            ])
                            .style(match (*index + 2 == selection, listing.selected) {
                                (true, true) => Style::new().underlined().fg(Color::Yellow),
                                (true, false) => Style::new().underlined(),
                                (false, true) => Style::new().fg(Color::Yellow),
                                (false, false) => Style::new(),
                            }),
                    );
                    *index = *index + 1;
                }

                if let Some(children) = &listing.children
                    && listing.open
                {
                    for child in children {
                        render(filter, selection, lines, index, &child);
                    }

                    if children.is_empty() {
                        lines.push(
                            Line::default()
                                .spans(vec!["        Empty folder".to_owned()])
                                .set_style(Style::new().fg(Color::Indexed(244))),
                        );
                    }
                } else if listing.children_state == ChildrenState::Loading && listing.open {
                    lines.push(
                        Line::default()
                            .spans(vec!["        Loading...".to_owned()])
                            .set_style(Style::new().fg(Color::Indexed(244))),
                    );
                }
            }

            render(
                filter_state.input(),
                *selection,
                &mut lines,
                &mut index,
                &*file_listings,
            );

            let display_width = files.width as isize;
            let display_height = files.height as isize;

            let max_width = lines.iter().map(Line::width).max().unwrap_or_default() as isize;
            let max_depth = lines.len() as isize;

            let max_width = (max_width - display_width).max(0) as usize;
            let max_height = (max_depth - display_height).max(0) as usize;

            *vertical_scroll_state = vertical_scroll_state.content_length(max_height);
            *horizontal_scroll_state = horizontal_scroll_state.content_length(max_width);

            let paragraph = Paragraph::new(lines).scroll((
                (*vertical_scroll).try_into().unwrap_or(0xFFFF),
                (*horizontal_scroll).try_into().unwrap_or(0xFFFF),
            ));

            frame.render_widget(
                paragraph,
                files.inner(Margin {
                    vertical: 1,
                    horizontal: 1,
                }),
            );

            frame.render_stateful_widget(
                Scrollbar::new(ratatui::widgets::ScrollbarOrientation::VerticalRight),
                files.inner(Margin {
                    vertical: 2,
                    horizontal: 1,
                }),
                vertical_scroll_state,
            );

            frame.render_stateful_widget(
                Scrollbar::new(ratatui::widgets::ScrollbarOrientation::HorizontalBottom),
                files.inner(Margin {
                    vertical: 1,
                    horizontal: 2,
                }),
                horizontal_scroll_state,
            );
        }
        Some(AddCheckWizardState::HttpStage1 {
            selection,
            host,
            port,
            uri,
            auto_setup,
            connect_error,
        }) => {
            frame.render_widget(Block::bordered().title("HTTP Check Setup Wizard"), area);

            let [
                err_block,
                submit,
                host_block,
                port_block,
                uri_block,
                auto_setup_block,
            ] = Layout::vertical([
                Constraint::Length(if connect_error.is_some() { 3 } else { 0 }),
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .areas(area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }));

            if let Some(err) = connect_error {
                frame.render_widget(
                    Block::bordered()
                        .title("Connection error!")
                        .title_style(Style::new().red()),
                    err_block,
                );
                frame.render_widget(
                    Line::raw(err.clone()),
                    err_block.inner(Margin {
                        vertical: 1,
                        horizontal: 1,
                    }),
                );
            }

            let submit_style = if *selection == 0 && selected {
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

            host.set_selected(*selection == 1 && selected);
            frame.render_stateful_widget(
                ErrorTextInput::default()
                    .label(Some("Host/IP:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                host_block,
                host,
            );
            if *selection == 1 && selected {
                ErrorTextInput::default().set_cursor_position(host_block, frame, host);
            }

            port.set_selected(*selection == 2 && selected);
            frame.render_stateful_widget(
                ErrorTextInput::default()
                    .label(Some("Port:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                port_block,
                port,
            );
            if *selection == 2 && selected {
                ErrorTextInput::default().set_cursor_position(port_block, frame, port);
            }

            uri.set_selected(*selection == 3 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("URI:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                uri_block,
                uri,
            );
            if *selection == 3 && selected {
                TextInput::default().set_cursor_position(uri_block, frame, uri);
            }

            frame.render_widget(
                Line::raw(&format!(
                    "[{}] Auto setup",
                    if *auto_setup { "X" } else { " " }
                ))
                .style(if *selection == 4 && selected {
                    Style::new().fg(Color::Yellow)
                } else {
                    Style::new()
                }),
                auto_setup_block,
            );
        }
        Some(AddCheckWizardState::SshStage1 {
            selection,
            host,
            username,
        }) => {
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

            let submit_style = if *selection == 0 && selected {
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

            host.set_selected(*selection == 1 && selected);
            frame.render_stateful_widget(
                ErrorTextInput::default()
                    .label(Some("Host/IP:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                host_block,
                host,
            );
            if *selection == 1 && selected {
                ErrorTextInput::default().set_cursor_position(host_block, frame, host);
            }

            username.set_selected(*selection == 2 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("URI:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                user_block,
                username,
            );
            if *selection == 2 && selected {
                TextInput::default().set_cursor_position(user_block, frame, username);
            }
        }
        Some(AddCheckWizardState::Generalize {
            row_selection,
            tab_selection,
            check_fields,
            ..
        }) => {
            frame.render_widget(Block::bordered().title("Confirm check settings"), area);

            let mut working_area = area.inner(Margin {
                vertical: 1,
                horizontal: 1,
            });

            if *row_selection == 0 {
                let mut tabs_area = working_area.clone();
                tabs_area.height = 1;
                tabs_area.x += 1;

                frame.render_widget(
                    Tabs::new(vec!["Next", "Cancel"])
                        .style(Style::default().white())
                        .highlight_style(if *row_selection == 0 && selected {
                            Style::new().bg(Color::Yellow)
                        } else {
                            Style::new().fg(Color::Yellow)
                        })
                        .select(*tab_selection),
                    tabs_area,
                );

                working_area.height = working_area.height.saturating_sub(1);
                working_area.y += 1;
            }

            let mut inputs = check_fields[row_selection.saturating_sub(1)..]
                .iter_mut()
                .enumerate();
            while working_area.height > 0
                && let Some((i, (key, input_state))) = inputs.next()
            {
                let mut editor_area = working_area.clone();
                editor_area.height = 3;

                input_state.set_selected(i == 0 && selected && *row_selection > 0);
                frame.render_stateful_widget(
                    ErrorTextInput::default()
                        .label(Some(key))
                        .selected_style(Some(Style::new().fg(Color::Yellow))),
                    editor_area,
                    input_state,
                );

                if i == 0 && selected && *row_selection > 0 {
                    ErrorTextInput::default().set_cursor_position(editor_area, frame, input_state);
                }

                working_area.height = working_area.height.saturating_sub(3);
                working_area.y += 3;
            }
        }
        Some(AddCheckWizardState::Finalize {
            selection,
            tab_selection,
            host,
            service,
            ..
        }) => {
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
                    .highlight_style(if *selection == 0 && selected {
                        Style::new().bg(Color::Yellow)
                    } else {
                        Style::new().fg(Color::Yellow)
                    })
                    .select(*tab_selection),
                submit,
            );

            host.set_selected(*selection == 1 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("Host name:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                host_block,
                host,
            );
            if *selection == 1 && selected {
                TextInput::default().set_cursor_position(host_block, frame, host);
            }

            service.set_selected(*selection == 2 && selected);
            frame.render_stateful_widget(
                TextInput::default()
                    .label(Some("Check name:"))
                    .selected_style(Some(Style::new().fg(Color::Yellow))),
                query_block,
                service,
            );
            if *selection == 2 && selected {
                TextInput::default().set_cursor_position(query_block, frame, service);
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
            Some(&"SSH") => Some(AddCheckWizardState::SshStage1 {
                selection: 0,
                host: ErrorTextInputState::new(ip_parser.clone() as Box<_>)
                    .set_input("127.0.0.1".to_string()),
                username: TextInputState::default().set_input("root".to_string()),
            }),
            Some(&"DNS") => Some(AddCheckWizardState::DnsStage1 {
                selection: 0,
                host: ErrorTextInputState::new(ip_parser.clone() as Box<_>)
                    .set_input("127.0.0.1".to_string()),
                query: TextInputState::default().set_input("google.com".to_string()),
            }),
            Some(&"HTTP") => Some(AddCheckWizardState::HttpStage1 {
                selection: 0,
                host: ErrorTextInputState::new(ip_parser.clone() as Box<_>)
                    .set_input("127.0.0.1".to_string()),
                port: ErrorTextInputState::new(port_parser.clone() as Box<_>)
                    .set_input("80".to_string()),
                uri: TextInputState::default().set_input("/".to_string()),
                auto_setup: true,
                connect_error: None,
            }),
            Some(&"FTP") => Some(AddCheckWizardState::FtpStage1 {
                selection: 0,
                host: ErrorTextInputState::new(ip_parser.clone() as Box<_>)
                    .set_input("127.0.0.1".to_string()),
                username: TextInputState::default().set_input("anonymous".to_string()),
                password: TextInputState::default(),
                root_dir: TextInputState::default().set_input("/".to_string()),
                auto_setup: true,
                connect_error: None,
            }),
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
        Some(AddCheckWizardState::DnsStage1 {
            selection,
            host,
            query,
        }) => {
            if let KeyCode::Char('n') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                *selection = (*selection + 1).min(2);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Down = key.code {
                *selection = (*selection + 1).min(2);
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::BackTab = key.code {
                if *selection == 0 {
                    *selection = 2;
                } else {
                    *selection = *selection - 1;
                }
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Tab = key.code {
                *selection = *selection + 1;
                if *selection == 3 {
                    *selection = 0;
                }
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::Char('p') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                if *selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *selection = selection.saturating_sub(1);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Up = key.code {
                if *selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *selection = selection.saturating_sub(1);
                tui.buffer.clear();
                return true;
            }

            if *selection == 1 {
                host.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if *selection == 2 {
                query.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if *selection == 0 {
                if let KeyCode::Char(' ') | KeyCode::Enter = key.code {
                    let Ok(addr) = host.parse() else {
                        tui.buffer.clear();
                        return true;
                    };

                    let Ok(serde_json::Value::Object(check_type)) =
                        serde_json::to_value(&crate::checks::dns::Dns {
                            host: addr,
                            domain: query.input().to_string(),
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

                    tui.add_check_tab.wizard_state = Some(AddCheckWizardState::Generalize {
                        row_selection: 0,
                        tab_selection: 0,
                        check_type: "dns",
                        check_fields,
                    });

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

            false
        }
        Some(AddCheckWizardState::FtpStage1 {
            selection,
            host,
            username,
            password,
            root_dir,
            auto_setup,
            ..
        }) => {
            if let KeyCode::Char('n') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                *selection = (*selection + 1).min(5);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Down = key.code {
                *selection = (*selection + 1).min(5);
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::BackTab = key.code {
                if *selection == 0 {
                    *selection = 5;
                } else {
                    *selection = *selection - 1;
                }
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Tab = key.code {
                *selection = *selection + 1;
                if *selection == 6 {
                    *selection = 0;
                }
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::Char('p') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                if *selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *selection = selection.saturating_sub(1);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Up = key.code {
                if *selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *selection = selection.saturating_sub(1);
                tui.buffer.clear();
                return true;
            }

            if *selection == 1 {
                host.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if *selection == 2 {
                username.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if *selection == 3 {
                password.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if *selection == 4 {
                root_dir.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if *selection == 5
                && let KeyCode::Char(' ') | KeyCode::Enter = key.code
            {
                *auto_setup = !*auto_setup;
                tui.buffer.clear();
                return true;
            }

            if *selection == 0 {
                if let KeyCode::Char(' ') | KeyCode::Enter = key.code
                    && tui.check_setup_task.is_none()
                {
                    let Ok(host) = host.parse() else {
                        tui.buffer.clear();
                        return true;
                    };

                    let Ok(password_value) = password.input().to_owned().parse();

                    let Ok(serde_json::Value::Object(check_type)) =
                        serde_json::to_value(&crate::checks::ftp::FtpTroubleshooter {
                            host,
                            user: username.input().to_owned(),
                            password: password_value,
                            ..Default::default()
                        })
                    else {
                        tui.buffer.clear();
                        return true;
                    };

                    if *auto_setup {
                        tui.check_setup_task = {
                            let host = host.clone();
                            let username = username.input().to_owned();
                            let password = password.input().to_owned();
                            let root_dir = root_dir.input().to_owned();
                            Some((
                                Box::pin(async move {
                                    let (client_session, file_listings) = tokio::task::spawn_blocking({
                                        let username = username.clone();
                                        let password = password.clone();
                                        let root_dir = root_dir.clone();

                                        move || -> eyre::Result<(ftp::FtpStream, RemoteFileListing)> {
                                            let mut stream =
                                                ftp::FtpStream::connect(format!("{host}:21"))?;
                                            stream.login(&username, &password)?;

                                            stream.cwd(&root_dir)?;

                                            let regex = provide_ftp_listing_regex();

                                            let file_listings =
                                                stream
                                                .list(None)?
                                                .into_iter()
                                                .filter_map(|row| parse_file_listing(&root_dir, &regex, &row))
                                                .collect::<Vec<_>>();

                                            let file_listings = RemoteFileListing {
                                                name: root_dir,
                                                selected: false,
                                                is_dir: true,
                                                children_state: ChildrenState::Loaded,
                                                children: Some(file_listings),
                                                open: true
                                            };

                                            Ok((stream, file_listings))
                                        }
                                    })
                                    .await??;

                                    let client_session = Arc::new(Mutex::new(client_session));

                                    Ok(Box::new(move |tui: &mut Tui<'_>| {
                                        tui.add_check_tab.wizard_state =
                                            Some(AddCheckWizardState::FtpStage2 {
                                                selection: 0,
                                                vertical_scroll: 0,
                                                horizontal_scroll: 0,
                                                vertical_scroll_state: Default::default(),
                                                horizontal_scroll_state: Default::default(),
                                                err_message: None,
                                                tab_selection: 0,
                                                clear_password: true,
                                                host,
                                                username,
                                                password,
                                                client_session,
                                                file_listings,
                                                filter_state: TextInputState::default(),
                                            });
                                    }) as Box<_>)
                                }),
                                Box::new(|tui, report| {
                                    if let Some(AddCheckWizardState::FtpStage1 {
                                        connect_error,
                                        ..
                                    }) = &mut tui.add_check_tab.wizard_state
                                    {
                                        *connect_error = Some(format!("{report}"));
                                    }
                                }),
                            ))
                        };
                    } else {
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
                                                crate::checks::ftp::FtpTroubleshooter,
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

                        tui.add_check_tab.wizard_state = Some(AddCheckWizardState::Generalize {
                            row_selection: 0,
                            tab_selection: 0,
                            check_type: "ftp",
                            check_fields,
                        });
                    }
                } else if let KeyCode::Char(' ') | KeyCode::Enter = key.code {
                    tui.check_setup_task = None;
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

            false
        }
        Some(AddCheckWizardState::FtpStage2 {
            selection,
            clear_password,
            tab_selection,
            filter_state,
            file_listings,
            client_session,
            horizontal_scroll,
            vertical_scroll,
            err_message,
            host,
            username,
            password,
            ..
        }) => {
            fn set_vertical_scroll(
                rendered_selection_height: usize,
                selection: usize,
                rendering_err: bool,
                vertical_scroll: &mut usize,
            ) {
                if selection < 2 {
                    return;
                }

                let Ok(size) = crossterm::terminal::window_size() else {
                    return;
                };

                let selection = selection - 2;

                // 13
                // 3 for bottom borders, 1 for bottom command buffer
                // 3 for top borders
                // 3 for file filter block
                // 2 for tab spaces, 1 for clear password input
                // 16 if error
                let scroll_area = size.rows - if rendering_err { 16 } else { 13 };

                if selection < 3 {
                    *vertical_scroll = 0;
                    return;
                }

                let vs = *vertical_scroll as isize;
                let current = rendered_selection_height as isize;
                let scroll_area = scroll_area as isize;

                if current - vs < 3 {
                    *vertical_scroll = (current - 3) as usize;
                    return;
                }

                if (scroll_area + vs) - current < 3 {
                    *vertical_scroll = (current + 3 - scroll_area) as usize;
                    return;
                }
            }

            fn render_height(
                filter: &str,
                selection: usize,
                listing: &RemoteFileListing,
            ) -> (usize, usize, usize) {
                fn render_height_internal(
                    filter: &str,
                    selection: usize,
                    selection_count: &mut usize,
                    render_height: &mut usize,
                    rendered_selection_height: &mut usize,
                    index: &mut usize,
                    listing: &RemoteFileListing,
                ) {
                    if listing.name.contains(filter) {
                        *selection_count += 1;
                        *render_height += 1;
                        *index += 1;
                        if *index <= selection {
                            *rendered_selection_height += 1;
                        }
                    }

                    if let Some(children) = &listing.children
                        && listing.open
                    {
                        for child in children {
                            render_height_internal(
                                filter,
                                selection,
                                selection_count,
                                render_height,
                                rendered_selection_height,
                                index,
                                child,
                            );
                        }

                        if children.is_empty() {
                            *render_height += 1;
                            if *index <= selection {
                                *rendered_selection_height += 1;
                            }
                        }
                    } else if listing.children_state == ChildrenState::Loading && listing.open {
                        *render_height += 1;
                        if *index <= selection {
                            *rendered_selection_height += 1;
                        }
                    }
                }

                let mut selection_count = 0;
                let mut render_height = 0;
                let mut rendered_selection_height = 0;
                let mut index = 0;
                render_height_internal(
                    filter,
                    selection,
                    &mut selection_count,
                    &mut render_height,
                    &mut rendered_selection_height,
                    &mut index,
                    listing,
                );
                (selection_count, render_height, rendered_selection_height)
            }

            let (selection_count, _, rendered_selection_height) =
                render_height(filter_state.input(), *selection, file_listings);

            if let KeyCode::Char('n') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                *selection = (*selection + 1).min(selection_count.max(1) + 1);
                tui.buffer.clear();
                set_vertical_scroll(
                    rendered_selection_height,
                    *selection,
                    err_message.is_some(),
                    vertical_scroll,
                );
                return true;
            } else if let KeyCode::Down = key.code {
                *selection = (*selection + 1).min(selection_count.max(1) + 1);
                tui.buffer.clear();
                set_vertical_scroll(
                    rendered_selection_height,
                    *selection,
                    err_message.is_some(),
                    vertical_scroll,
                );
                return true;
            }

            if let KeyCode::BackTab = key.code {
                if *selection == 0 {
                    *selection = selection_count + 1;
                } else {
                    *selection = *selection - 1;
                }
                tui.buffer.clear();
                set_vertical_scroll(
                    rendered_selection_height,
                    *selection,
                    err_message.is_some(),
                    vertical_scroll,
                );
                return true;
            } else if let KeyCode::Tab = key.code {
                *selection = *selection + 1;
                if *selection == selection_count + 2 {
                    *selection = 0;
                }
                tui.buffer.clear();
                set_vertical_scroll(
                    rendered_selection_height,
                    *selection,
                    err_message.is_some(),
                    vertical_scroll,
                );
                return true;
            }

            if let KeyCode::Char('p') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                if *selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                } else {
                    *selection = selection.saturating_sub(1);
                }

                tui.buffer.clear();
                set_vertical_scroll(
                    rendered_selection_height,
                    *selection,
                    err_message.is_some(),
                    vertical_scroll,
                );
                return true;
            } else if let KeyCode::Up = key.code {
                if *selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                } else {
                    *selection = selection.saturating_sub(1);
                }

                tui.buffer.clear();
                set_vertical_scroll(
                    rendered_selection_height,
                    *selection,
                    err_message.is_some(),
                    vertical_scroll,
                );
                return true;
            }

            if *selection == 0 {
                if is_generic_left(key) {
                    *tab_selection = tab_selection.saturating_sub(1);
                    tui.buffer.clear();
                    return true;
                }
                if is_generic_right(key) {
                    *tab_selection = tab_selection.saturating_add(1).min(1);
                    tui.buffer.clear();
                    return true;
                }

                if let KeyCode::Char(' ') | KeyCode::Enter = key.code {
                    if *tab_selection == 1 {
                        tui.add_check_tab.wizard_state = None;
                        tui.buffer.clear();
                        return true;
                    }

                    if tui.check_setup_task.is_some() {
                        tui.buffer.clear();
                        return true;
                    }

                    fn path_listing(listing: &RemoteFileListing) -> Vec<(String, bool)> {
                        listing
                            .selected
                            .then(|| (listing.name.clone(), listing.is_dir))
                            .into_iter()
                            .chain(
                                listing
                                    .children
                                    .iter()
                                    .flat_map(|children| children.iter().flat_map(path_listing)),
                            )
                            .collect()
                    }

                    fn recursive_list_files(
                        regex: &regex::Regex,
                        stream: &mut ::ftp::FtpStream,
                        dir: &str,
                    ) -> eyre::Result<Vec<Result<String, String>>> {
                        Ok(stream
                            .list(Some(dir))?
                            .into_iter()
                            .filter_map(|row| {
                                eprintln!("Row found: {row}");
                                let listing = parse_file_listing(dir, regex, &row)?;
                                eprintln!("Here");
                                Some(
                                    if listing.is_dir {
                                        recursive_list_files(regex, stream, dir)
                                    } else {
                                        Ok(vec![Ok(listing.name.clone())])
                                    }
                                    .unwrap_or_else(|e| {
                                        vec![Err(format!(
                                            "# Could not download directory {dir}: {e}"
                                        ))]
                                    }),
                                )
                            })
                            .flat_map(|p| p)
                            .collect())
                    }

                    tui.check_setup_task = {
                        let session = Arc::clone(&client_session);
                        let file_listings = file_listings.clone();
                        let host = *host;
                        let username = username.clone();
                        let password = password.clone();
                        let clear_password = *clear_password;
                        Some((
                            Box::pin(async move {
                                let hashes = tokio::task::spawn_blocking({
                                    move || -> eyre::Result<Vec<String>> {
                                        let path_list = path_listing(&file_listings);

                                        let Ok(mut session) = session.lock() else {
                                            eyre::bail!("Could not lock the FTP client session");
                                        };

                                        let regex = provide_ftp_listing_regex();

                                        eprintln!("Path list: {path_list:?}");

                                        Ok(path_list
                                            .into_iter()
                                            .flat_map(|(path, is_dir)| {
                                                if is_dir {
                                                    recursive_list_files(
                                                        &regex,
                                                        &mut *session,
                                                        &path,
                                                    )
                                                    .unwrap_or_else(|e| {
                                                        vec![Err(format!(
                                                            "# Could not download directory {path}: {e}"
                                                        ))]
                                                    })
                                                } else {
                                                    vec![Ok(path)]
                                                }
                                            })
                                            // Why collect and allocate here?
                                            // Because the FTP session is borrowed in the closure above. It can't
                                            // be used again in the closure below until the closure above is no longer
                                            // referenced
                                            .collect::<Vec<_>>()
                                            .into_iter()
                                            .map(|path| {
                                                path.and_then(|p| {
                                                    session
                                                        .retr(&p, |reader| {
                                                            let mut hasher = sha2::Sha256::new();
                                                            let mut buffer = [0u8; 8192];
                                                            loop {
                                                                let n = reader
                                                                .read(&mut buffer)
                                                                .map_err(
                                                                ::ftp::FtpError::ConnectionError,
                                                            )?;
                                                                if n == 0 {
                                                                    break;
                                                                }
                                                                hasher.update(&buffer[..n]);
                                                            }
                                                            Ok(format!("{} {:x}", p, hasher.finalize()))
                                                        })
                                                        .map_err(|e| {
                                                            format!(
                                                                "# Could not download file {p}: {e}"
                                                            )
                                                        })
                                                })
                                                .unwrap_or_else(|e| e)
                                            })
                                            .collect::<Vec<_>>())
                                    }
                                })
                                .await??;

                                let file_name = format!("check-ftp-{host}.sha256");
                                let mut pwd = std::env::current_dir()?;
                                pwd.push(&file_name);

                                let mut file = tokio::io::BufWriter::new(
                                    tokio::fs::OpenOptions::new()
                                        .create(true)
                                        .write(true)
                                        .truncate(true)
                                        .open(&file_name)
                                        .await?,
                                );

                                file.write_all(
                                    &format!("# Generated on {}\n", Utc::now()).as_bytes(),
                                )
                                .await?;

                                dbg!(&hashes);

                                for line in hashes {
                                    file.write(line.as_bytes()).await?;
                                    file.write("\n".as_bytes()).await?;
                                }

                                file.flush().await?;

                                drop(file);

                                let check_type = match serde_json::to_value(
                                    &crate::checks::ftp::FtpTroubleshooter {
                                        host,
                                        user: username,
                                        password: if clear_password {
                                            CheckValue::stdin()
                                        } else {
                                            CheckValue::string(password)
                                        },
                                        compare_hash: Some(format!("{}", pwd.display())),
                                        ..Default::default()
                                    },
                                ) {
                                    Ok(serde_json::Value::Object(check_type)) => check_type,
                                    Err(e) => {
                                        eyre::bail!("Could not serialize FTP check; {e}");
                                    }
                                    _ => {
                                        eyre::bail!("Could not serialize FTP check; unknown error");
                                    }
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

                                Ok(Box::new(|tui: &mut Tui<'_>| {
                                    tui.add_check_tab.wizard_state =
                                        Some(AddCheckWizardState::Generalize {
                                            row_selection: 0,
                                            tab_selection: 0,
                                            check_type: "ftp",
                                            check_fields,
                                        });
                                }) as Box<_>)
                            }),
                            Box::new(move |tui, report| {
                                if let Some(AddCheckWizardState::FtpStage2 {
                                    err_message, ..
                                }) = &mut tui.add_check_tab.wizard_state
                                {
                                    *err_message = Some(format!("{report}"));
                                }
                            }),
                        ))
                    };

                    tui.buffer.clear();
                    return true;
                }
            }

            if *selection == 1 {
                *clear_password = !*clear_password;
                tui.buffer.clear();
                return true;
            }

            // Assumption: if we want a good parent_index value,
            // we're never calling this with selection equal to 0
            fn find_listing<'a, 'b>(
                index: &'a mut usize,
                selection: usize,
                parent_index: usize,
                listing: &'b mut RemoteFileListing,
            ) -> Option<(usize, &'b mut RemoteFileListing)> {
                if *index == selection {
                    return Some((parent_index, listing));
                }
                let current_index = *index;
                *index += 1;
                if listing.is_dir && listing.open {
                    if let Some(children) = listing.children.as_mut() {
                        for child in children.iter_mut() {
                            if let Some((parent_index, found)) =
                                find_listing(index, selection, current_index, child)
                            {
                                return Some((parent_index, found));
                            }
                        }
                    }
                }
                None
            }

            fn find_listing_by_path<'a, 'b>(
                path: &str,
                listing: &'b mut RemoteFileListing,
            ) -> Option<&'b mut RemoteFileListing> {
                if path == listing.name {
                    return Some(listing);
                }
                if !listing.name.starts_with(path) && !path.starts_with(&listing.name) {
                    return None;
                }
                if listing.is_dir {
                    if let Some(children) = listing.children.as_mut() {
                        for child in children.iter_mut() {
                            if let Some(found) = find_listing_by_path(path, child) {
                                return Some(found);
                            }
                        }
                    }
                }
                None
            }

            if *selection > 1 {
                if let KeyCode::Char('0') = key.code
                    && *horizontal_scroll > 0
                {
                    *horizontal_scroll = 0;
                    tui.buffer.clear();
                    return true;
                }

                if let KeyCode::Left = key.code {
                    let mut current_index = 0;
                    let mut listing_find_result =
                        find_listing(&mut current_index, *selection - 2, 0, file_listings);
                    if let Some((parent_index, listing)) = listing_find_result.as_mut()
                        && *selection > 2
                    {
                        if listing.is_dir && listing.open {
                            listing.open = false;
                        } else {
                            *selection = *parent_index + 2;
                            let (_, _, rendered_selection_height) =
                                render_height(filter_state.input(), *selection, file_listings);
                            set_vertical_scroll(
                                rendered_selection_height,
                                *selection,
                                err_message.is_some(),
                                vertical_scroll,
                            );
                        }
                    } else {
                        *horizontal_scroll = horizontal_scroll.saturating_sub(1);
                    }

                    tui.buffer.clear();
                    return true;
                }

                if let KeyCode::Right = key.code {
                    let mut current_index = 0;
                    if let Some((_, listing)) =
                        find_listing(&mut current_index, *selection - 2, 0, file_listings)
                        && listing.is_dir
                        && !listing.open
                    {
                        if listing.children_state == ChildrenState::NotLoaded
                            && tui.check_setup_task.is_none()
                        {
                            listing.children_state = ChildrenState::Loading;
                            tui.check_setup_task = {
                                let session = Arc::clone(&client_session);
                                let path = listing.name.clone();
                                let err_path = listing.name.clone();
                                Some((
                                    Box::pin(async move {
                                        let new_listings = tokio::task::spawn_blocking({
                                            let path = path.clone();
                                            move || -> eyre::Result<Vec<RemoteFileListing>> {
                                                let Ok(mut session) = session.lock() else {
                                                    eyre::bail!(
                                                        "Could not lock the FTP client session"
                                                    );
                                                };

                                                let regex = provide_ftp_listing_regex();

                                                Ok(session
                                                    .list(Some(&path))?
                                                    .into_iter()
                                                    .filter_map(|row| {
                                                        parse_file_listing(&path, &regex, &row)
                                                    })
                                                    .collect::<Vec<_>>())
                                            }
                                        })
                                        .await??;

                                        Ok(Box::new(move |tui: &mut Tui<'_>| {
                                            if let Some(AddCheckWizardState::FtpStage2 {
                                                file_listings,
                                                ..
                                            }) = &mut tui.add_check_tab.wizard_state
                                            {
                                                if let Some(listing) =
                                                    find_listing_by_path(&path, file_listings)
                                                {
                                                    listing.open = true;
                                                    listing.children = Some(new_listings);
                                                    listing.children_state = ChildrenState::Loaded;
                                                }
                                            }
                                        }) as Box<_>)
                                    }),
                                    Box::new(move |tui, report| {
                                        if let Some(AddCheckWizardState::FtpStage2 {
                                            err_message,
                                            file_listings,
                                            ..
                                        }) = &mut tui.add_check_tab.wizard_state
                                        {
                                            *err_message = Some(format!("{report}"));
                                            if let Some(listing) =
                                                find_listing_by_path(&err_path, file_listings)
                                            {
                                                listing.children_state = ChildrenState::NotLoaded;
                                            }
                                        }
                                    }),
                                ))
                            };
                        } else {
                            listing.open = true;
                        }
                    } else {
                        *horizontal_scroll += 1;
                    }

                    tui.buffer.clear();
                    return true;
                }

                if let KeyCode::Enter = key.code {
                    let mut current_index = 0;
                    if let Some((_, listing)) =
                        find_listing(&mut current_index, *selection - 2, 0, file_listings)
                    {
                        let selected = !listing.selected;

                        fn set_selected(listing: &mut RemoteFileListing, selected: bool) {
                            listing.selected = selected;
                            if let Some(children) = listing.children.as_mut() {
                                for child in children.iter_mut() {
                                    set_selected(child, selected);
                                }
                            }
                        }
                        set_selected(listing, selected);
                    }
                    tui.buffer.clear();
                    return true;
                }

                filter_state.handle_keybind(*key);
                let (_, _, rendered_selection_height) =
                    render_height(filter_state.input(), *selection, file_listings);
                *selection = (*selection).min(rendered_selection_height);
                set_vertical_scroll(
                    rendered_selection_height,
                    *selection,
                    err_message.is_some(),
                    vertical_scroll,
                );
                tui.buffer.clear();
                return true;
            }

            // prevent interacting with the UI in the background
            if let KeyCode::Char(' ') = key.code {
                tui.buffer.clear();
                return true;
            }

            false
        }
        Some(AddCheckWizardState::HttpStage1 {
            selection,
            host,
            port,
            uri,
            auto_setup,
            ..
        }) => {
            if let KeyCode::Char('n') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                *selection = (*selection + 1).min(5);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Down = key.code {
                *selection = (*selection + 1).min(5);
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::BackTab = key.code {
                if *selection == 0 {
                    *selection = 5;
                } else {
                    *selection = *selection - 1;
                }
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Tab = key.code {
                *selection = *selection + 1;
                if *selection == 6 {
                    *selection = 0;
                }
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::Char('p') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                if *selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *selection = selection.saturating_sub(1);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Up = key.code {
                if *selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *selection = selection.saturating_sub(1);
                tui.buffer.clear();
                return true;
            }

            if *selection == 1 {
                host.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if *selection == 2 {
                port.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if *selection == 3 {
                uri.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if *selection == 4
                && let KeyCode::Char(' ') | KeyCode::Enter = key.code
            {
                *auto_setup = !*auto_setup;
                tui.buffer.clear();
                return true;
            }

            if *selection == 0 {
                if let KeyCode::Char(' ') | KeyCode::Enter = key.code
                    && tui.check_setup_task.is_none()
                {
                    let Ok(host) = host.parse() else {
                        tui.buffer.clear();
                        return true;
                    };
                    let Ok(port) = port.parse() else {
                        tui.buffer.clear();
                        return true;
                    };

                    let Ok(serde_json::Value::Object(mut check_type)) =
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

                    if *auto_setup {
                        tui.check_setup_task = {
                            let host = host.clone();
                            let port = port.clone();
                            let uri = uri.input().to_owned();
                            Some((
                                Box::pin(async move {
                                    let client = reqwest::Client::new();

                                    let copy1 = client
                                        .get(format!(
                                            "http://{host}:{port}{}{uri}",
                                            if uri.starts_with('/') { "" } else { "/" }
                                        ))
                                        .send()
                                        .await?;

                                    let status = copy1.status();
                                    let copy1 = copy1.text().await?;

                                    let file_name =
                                        format!("check-http-{host}-{port}-reference.html");

                                    tokio::fs::write(&file_name, &copy1).await?;

                                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

                                    let client = reqwest::Client::new();

                                    let copy2 = client
                                        .get(format!(
                                            "http://{host}:{port}{}{uri}",
                                            if uri.starts_with('/') { "" } else { "/" }
                                        ))
                                        .send()
                                        .await?
                                        .text()
                                        .await?;

                                    let difference_count: u32 = {
                                        use imara_diff::{Algorithm, Diff, InternedInput};

                                        let input = InternedInput::new(&*copy1, &*copy2);
                                        let diff = Diff::compute(Algorithm::Histogram, &input);

                                        diff.hunks()
                                            .map(|hunk| {
                                                (hunk.before.end - hunk.before.start)
                                                    + (hunk.after.end - hunk.after.start)
                                            })
                                            .sum()
                                    };

                                    let pwd = std::env::current_dir()?;
                                    check_type.insert(
                                        "reference_file".into(),
                                        format!("{}/{file_name}", pwd.display()).into(),
                                    );
                                    check_type.insert(
                                        "reference_difference_count".into(),
                                        difference_count.into(),
                                    );
                                    check_type
                                        .insert("valid_status".into(), status.as_u16().into());

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

                                    Ok(Box::new(|tui: &mut Tui<'_>| {
                                        tui.add_check_tab.wizard_state =
                                            Some(AddCheckWizardState::Generalize {
                                                row_selection: 0,
                                                tab_selection: 0,
                                                check_type: "http",
                                                check_fields,
                                            });
                                    }) as Box<_>)
                                }),
                                Box::new(|tui, report| {
                                    if let Some(AddCheckWizardState::HttpStage1 {
                                        connect_error,
                                        ..
                                    }) = &mut tui.add_check_tab.wizard_state
                                    {
                                        *connect_error = Some(format!("{report}"));
                                    }
                                }),
                            ))
                        };
                    } else {
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

                        tui.add_check_tab.wizard_state = Some(AddCheckWizardState::Generalize {
                            row_selection: 0,
                            tab_selection: 0,
                            check_type: "http",
                            check_fields,
                        });
                    }

                    tui.buffer.clear();
                    return true;
                } else if let KeyCode::Char(' ') | KeyCode::Enter = key.code {
                    tui.check_setup_task = None;
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

            false
        }
        Some(AddCheckWizardState::SshStage1 {
            selection,
            host,
            username,
        }) => {
            if let KeyCode::Char('n') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                *selection = (*selection + 1).min(2);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Down = key.code {
                *selection = (*selection + 1).min(2);
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::BackTab = key.code {
                if *selection == 0 {
                    *selection = 2;
                } else {
                    *selection = *selection - 1;
                }
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Tab = key.code {
                *selection = *selection + 1;
                if *selection == 3 {
                    *selection = 0;
                }
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::Char('p') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                if *selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *selection = selection.saturating_sub(1);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Up = key.code {
                if *selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *selection = selection.saturating_sub(1);
                tui.buffer.clear();
                return true;
            }

            if *selection == 1 {
                host.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if *selection == 2 {
                username.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if *selection == 0 {
                if let KeyCode::Char(' ') | KeyCode::Enter = key.code {
                    let Ok(host) = host.parse() else {
                        tui.buffer.clear();
                        return true;
                    };

                    let Ok(serde_json::Value::Object(check_type)) =
                        serde_json::to_value(&crate::checks::ssh::SshTroubleshooter {
                            host,
                            user: username.input().to_owned(),
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

                    tui.add_check_tab.wizard_state = Some(AddCheckWizardState::Generalize {
                        row_selection: 0,
                        tab_selection: 0,
                        check_type: "ssh",
                        check_fields,
                    });

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

            false
        }
        Some(AddCheckWizardState::Generalize {
            row_selection,
            tab_selection,
            check_type,
            check_fields,
        }) => {
            if let KeyCode::Char('n') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                *row_selection = (*row_selection + 1).min(check_fields.len());
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Down = key.code {
                *row_selection = (*row_selection + 1).min(check_fields.len());
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::BackTab = key.code {
                if *row_selection == 0 {
                    *row_selection = check_fields.len();
                } else {
                    *row_selection = *row_selection - 1;
                }
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Tab = key.code {
                *row_selection = *row_selection + 1;
                if *row_selection == check_fields.len() + 1 {
                    *row_selection = 0;
                }
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::Char('p') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                if *row_selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *row_selection = row_selection.saturating_sub(1);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Up = key.code {
                if *row_selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *row_selection = row_selection.saturating_sub(1);
                tui.buffer.clear();
                return true;
            }

            if *row_selection == 0 {
                if is_generic_left(key) {
                    *tab_selection = tab_selection.saturating_sub(1);
                } else if is_generic_right(key) {
                    *tab_selection = tab_selection.saturating_add(1).min(1);
                }

                if *tab_selection == 0
                    && let KeyCode::Char(' ') | KeyCode::Enter = key.code
                {
                    let Ok(v) = check_fields
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

                    tui.add_check_tab.wizard_state = Some(AddCheckWizardState::Finalize {
                        selection: 0,
                        tab_selection: 0,
                        check: parsed,
                        host: TextInputState::default(),
                        service: TextInputState::default(),
                    });
                } else if *tab_selection == 1
                    && let KeyCode::Char(' ') | KeyCode::Enter = key.code
                {
                    tui.add_check_tab.wizard_state = None;
                }

                tui.buffer.clear();
                return true;
            } else if let Some((_, fields)) = check_fields.get_mut(*row_selection - 1) {
                fields.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if is_generic_up(key) {
                tui.buffer.clear();
                return true;
            }
            if is_generic_down(key) {
                tui.buffer.clear();
                return true;
            }

            false
        }
        Some(AddCheckWizardState::Finalize {
            selection,
            tab_selection,
            check,
            host,
            service,
        }) => {
            if let KeyCode::Char('n') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                *selection = (*selection + 1).min(2);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Down = key.code {
                *selection = (*selection + 1).min(2);
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::BackTab = key.code {
                if *selection == 0 {
                    *selection = 2;
                } else {
                    *selection = *selection - 1;
                }
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Tab = key.code {
                *selection = *selection + 1;
                if *selection == 3 {
                    *selection = 0;
                }
                tui.buffer.clear();
                return true;
            }

            if let KeyCode::Char('p') = key.code
                && key.modifiers == KeyModifiers::CONTROL
            {
                if *selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *selection = selection.saturating_sub(1);
                tui.buffer.clear();
                return true;
            } else if let KeyCode::Up = key.code {
                if *selection == 0 {
                    tui.current_selection = super::CurrentSelection::Tabs;
                    tui.buffer.clear();
                    return true;
                }

                *selection = selection.saturating_sub(1);
                tui.buffer.clear();
                return true;
            }

            if *selection == 1 {
                host.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if *selection == 2 {
                service.handle_keybind(*key);
                tui.buffer.clear();
                return true;
            }

            if *selection == 0 {
                if is_generic_left(key) {
                    *tab_selection = tab_selection.saturating_sub(1);
                } else if is_generic_right(key) {
                    *tab_selection = tab_selection.saturating_add(1).min(1);
                }

                if *tab_selection == 0
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
                            CheckId(Arc::from(host.input()), Arc::from(service.input())),
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
                    let mut config_parsed = std::fs::read(path)
                        .map_err(|_| ())
                        .and_then(|c| toml::from_slice::<DaemonConfig>(&c).map_err(|_| ()))
                        .unwrap_or_default();

                    let host = config_parsed.checks.entry(host.input().into());
                    let host = host.or_default();
                    host.insert(service.input().into(), check.clone());

                    if let Err(e) = toml::to_string_pretty(&config_parsed)
                        .map_err(|e| format!("{e}"))
                        .and_then(|c| std::fs::write(path, c).map_err(|e| format!("{e}")))
                    {
                        eprintln!("Could not save configuration: {e}");
                    }

                    tui.add_check_tab.wizard_state = None;
                    tui.current_tab = super::Tab::Checks;
                } else if *tab_selection == 1
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

fn provide_ftp_listing_regex() -> regex::Regex {
    regex::Regex::new(r"([d\-])(?:[r\-][w\-][x\-]){3}\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+[a-zA-Z]+\s+[0-9]+\s+[0-9]+:[0-9]+\s(.*)|[0-9]{2}-[0-9]{2}-[0-9]{2}\s+[0-9]{2}:[0-9]{2}[AP]M\s+(<DIR>|[0-9]+)\s+([^ ]+)").expect("Static regex failed compilation and testing")
}

fn parse_file_listing(
    root_dir: &str,
    regxp: &regex::Regex,
    listing: &str,
) -> Option<RemoteFileListing> {
    let capture = regxp.captures(listing)?;

    let is_dir = capture
        .get(1)
        .or(capture.get(3))
        .map_or(false, |m| m.as_str() == "d" || m.as_str() == "<DIR>");
    let name = capture
        .get(2)
        .or(capture.get(4))
        .map(|m| m.as_str().to_owned())?;

    Some(RemoteFileListing {
        name: format!(
            "{root_dir}{}{name}",
            if root_dir.ends_with('/') { "" } else { "/" }
        ),
        is_dir,
        selected: false,
        children_state: ChildrenState::NotLoaded,
        children: None,
        open: false,
    })
}
