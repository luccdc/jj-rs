use std::{marker::PhantomData, sync::Arc};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    buffer::Buffer,
    layout::Rect,
    prelude::Stylize,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph, StatefulWidget, Widget},
};

#[derive(Default)]
pub struct TextInputState {
    input: String,
    character_index: usize,
    horizontal_scroll: usize,
    selected: bool,
    bottom_title: Option<Span<'static>>,
    render_width: usize,
}

#[derive(Default, Clone)]
pub struct TextInput {
    label: Option<Arc<str>>,
    selected_style: Option<Style>,
}

impl TextInputState {
    fn word_back(&self) -> usize {
        self.input[..self.character_index]
            .rfind(' ')
            .unwrap_or_default()
    }

    fn word_forward(&self) -> usize {
        (self.input[(self.character_index + 1).min(self.input.len())..]
            .find(' ')
            .unwrap_or(self.input.len())
            + self.character_index
            + 1)
        .min(self.input.len())
    }

    fn reset_scroll(&mut self) {
        if self.character_index < 5 {
            self.horizontal_scroll = 0;
        } else if self.character_index - self.horizontal_scroll < 5 {
            self.horizontal_scroll = self.character_index - 5;
        } else if (self.render_width + self.horizontal_scroll).saturating_sub(self.character_index)
            < 5
        {
            self.horizontal_scroll = self.character_index + 5 - self.render_width;
        }
    }

    pub fn input(&self) -> &str {
        &self.input
    }

    pub fn set_input(self, input: String) -> Self {
        Self { input, ..self }
    }

    pub fn handle_keybind(&mut self, event: KeyEvent) -> bool {
        if let KeyCode::Enter = event.code {
            return true;
        }

        if let KeyCode::Backspace = event.code
            && event.modifiers == KeyModifiers::CONTROL
        {
            self.input
                .replace_range(self.word_back()..self.character_index, "");
        } else if let KeyCode::Backspace = event.code
            && event.modifiers.is_empty()
        {
            if self.character_index == 0 {
            } else if self.character_index == self.input.len() {
                self.input.pop();
                self.character_index = self.character_index.saturating_sub(1);
            } else {
                self.input.remove(self.character_index.saturating_sub(1));
                self.character_index = self.character_index.saturating_sub(1);
            }
        } else if let KeyCode::Delete = event.code
            && event.modifiers.is_empty()
        {
            if self.character_index + 1 < self.input.len() {
                self.input.remove(self.character_index);
            } else if self.character_index == self.input.len() {
                self.input.pop();
            }
        } else if let KeyCode::Left = event.code {
            self.character_index = self.character_index.saturating_sub(1);
        } else if let KeyCode::Right = event.code {
            self.character_index = self.character_index.saturating_add(1);
            if self.character_index > self.input.len() {
                self.character_index = self.input.len();
            }
        } else if let KeyCode::Char('f') = event.code
            && event.modifiers == KeyModifiers::ALT
        {
            self.character_index = self.word_forward();
        } else if let KeyCode::Char('b') = event.code
            && event.modifiers == KeyModifiers::ALT
        {
            self.character_index = self.word_back();
        } else if let KeyCode::Char('e') = event.code
            && event.modifiers == KeyModifiers::ALT
        {
            self.character_index = self.input.len();
        } else if let KeyCode::Char('a') = event.code
            && event.modifiers == KeyModifiers::CONTROL
        {
            self.character_index = 0;
        } else if let KeyCode::Char('u') = event.code
            && event.modifiers == KeyModifiers::CONTROL
        {
            self.input = String::new();
            self.character_index = 0;
        } else if let KeyCode::Char(c) = event.code {
            self.input.insert(self.character_index, c);
            self.character_index = self.character_index.saturating_add(1);
        }

        self.reset_scroll();
        return false;
    }

    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }
}

impl TextInput {
    pub fn label(self, label: Option<&str>) -> Self {
        Self {
            label: label.map(|l| Arc::from(l)),
            ..self
        }
    }

    pub fn selected_style(self, selected_style: Option<Style>) -> Self {
        Self {
            selected_style,
            ..self
        }
    }

    pub fn set_cursor_position(&self, area: Rect, frame: &mut Frame, state: &mut TextInputState) {
        if state.selected {
            frame.set_cursor_position((
                (area.x + 1).saturating_add(
                    state
                        .character_index
                        .saturating_sub(state.horizontal_scroll)
                        .try_into()
                        .unwrap_or(0xFFFF),
                ),
                area.y + 1,
            ));
        }
    }
}

impl StatefulWidget for TextInput {
    type State = TextInputState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let input_block = Block::bordered();
        let input_block = if let Some(label) = self.label {
            input_block.title(label.to_string())
        } else {
            input_block
        };
        let input_block = if let Some(label) = &state.bottom_title {
            input_block.title_bottom(label.clone())
        } else {
            input_block
        };
        let input_block = if state.selected
            && let Some(style) = self.selected_style
        {
            input_block.style(style)
        } else {
            input_block
        };

        let input_area = input_block.inner(area.clone());

        let input = Paragraph::new(vec![Line::from(state.input.clone())])
            .scroll((0, state.horizontal_scroll.try_into().unwrap_or(0xFFFF)))
            .style(Style::new().fg(Color::White));

        // remove borders
        state.render_width = (area.width - 2) as usize;

        Clear.render(area, buf);
        input_block.render(area, buf);
        input.render(input_area, buf);
    }
}

#[derive(Default)]
pub struct ErrorTextInputState<T, F>
where
    F: for<'a> Fn(&'a str) -> Result<T, String>,
{
    input: String,
    character_index: usize,
    horizontal_scroll: usize,
    selected: bool,
    render_width: usize,
    parse: F,
}

#[derive(Clone)]
pub struct ErrorTextInput<T, F> {
    label: Option<Arc<str>>,
    selected_style: Option<Style>,
    _t: PhantomData<T>,
    _f: PhantomData<F>,
}

impl<T, F> Default for ErrorTextInput<T, F> {
    fn default() -> Self {
        Self {
            label: Default::default(),
            selected_style: Default::default(),
            _t: PhantomData,
            _f: PhantomData,
        }
    }
}

impl<T, F> ErrorTextInputState<T, F>
where
    F: for<'a> Fn(&'a str) -> Result<T, String>,
{
    pub fn new(parse: F) -> Self {
        Self {
            parse,
            input: Default::default(),
            character_index: Default::default(),
            horizontal_scroll: Default::default(),
            selected: Default::default(),
            render_width: Default::default(),
        }
    }

    pub fn input(&self) -> &str {
        &self.input
    }

    pub fn parse(&self) -> Result<T, String> {
        (self.parse)(&self.input)
    }

    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    pub fn set_input(self, input: String) -> Self {
        Self { input, ..self }
    }

    pub fn handle_keybind(&mut self, event: KeyEvent) -> bool {
        let mut passthrough = TextInputState {
            character_index: self.character_index,
            horizontal_scroll: self.horizontal_scroll,
            input: self.input.clone(),
            selected: self.selected,
            render_width: self.render_width,
            bottom_title: None,
        };

        let done = passthrough.handle_keybind(event);

        self.character_index = passthrough.character_index;
        self.horizontal_scroll = passthrough.horizontal_scroll;
        self.input = passthrough.input;
        self.render_width = passthrough.render_width;
        self.selected = passthrough.selected;

        done
    }
}

impl<T, F> ErrorTextInput<T, F>
where
    F: for<'a> Fn(&'a str) -> Result<T, String>,
{
    pub fn label(self, label: Option<&str>) -> Self {
        Self {
            label: label.map(|l| Arc::from(l)),
            ..self
        }
    }

    pub fn selected_style(self, selected_style: Option<Style>) -> Self {
        Self {
            selected_style,
            ..self
        }
    }

    pub fn set_cursor_position(
        &self,
        area: Rect,
        frame: &mut Frame,
        state: &mut ErrorTextInputState<T, F>,
    ) {
        if state.selected {
            frame.set_cursor_position((
                (area.x + 1).saturating_add(
                    state
                        .character_index
                        .saturating_sub(state.horizontal_scroll)
                        .try_into()
                        .unwrap_or(0xFFFF),
                ),
                area.y + 1,
            ));
        }
    }
}

impl<T, F> StatefulWidget for ErrorTextInput<T, F>
where
    F: for<'a> Fn(&'a str) -> Result<T, String>,
{
    type State = ErrorTextInputState<T, F>;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let mut passthrough = TextInputState {
            character_index: state.character_index,
            horizontal_scroll: state.horizontal_scroll,
            input: state.input.clone(),
            render_width: state.render_width,
            selected: state.selected,
            bottom_title: (state.parse)(&state.input).err().map(|e| e.red()),
        };

        TextInput::default()
            .label(self.label.clone().as_deref())
            .selected_style(self.selected_style)
            .render(area.clone(), buf, &mut passthrough);

        state.render_width = passthrough.render_width;
    }
}
