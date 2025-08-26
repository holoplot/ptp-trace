use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};
use std::{
    io,
    time::{Duration, Instant},
};
use tokio::time;

use crate::types::{ClockIdentity, ProcessedPacket};

use crate::{
    ptp::{PtpHost, PtpHostState, PtpTracker},
    ui::ui,
};

#[derive(Debug, Clone, PartialEq)]
pub enum AppState {
    Running,
    Quitting,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SortColumn {
    ClockIdentity,
    IpAddress,
    State,
    Domain,
    Priority,
    ClockClass,
    SelectedTransmitter,
    MessageCount,
    LastSeen,
}

impl SortColumn {
    pub fn next(&self) -> Self {
        match self {
            SortColumn::State => SortColumn::ClockIdentity,
            SortColumn::ClockIdentity => SortColumn::IpAddress,
            SortColumn::IpAddress => SortColumn::Domain,
            SortColumn::Domain => SortColumn::Priority,
            SortColumn::Priority => SortColumn::ClockClass,
            SortColumn::ClockClass => SortColumn::SelectedTransmitter,
            SortColumn::SelectedTransmitter => SortColumn::MessageCount,
            SortColumn::MessageCount => SortColumn::LastSeen,
            SortColumn::LastSeen => SortColumn::State,
        }
    }

    pub fn previous(&self) -> Self {
        match self {
            SortColumn::LastSeen => SortColumn::MessageCount,
            SortColumn::MessageCount => SortColumn::SelectedTransmitter,
            SortColumn::SelectedTransmitter => SortColumn::ClockClass,
            SortColumn::ClockClass => SortColumn::Priority,
            SortColumn::Priority => SortColumn::Domain,
            SortColumn::Domain => SortColumn::IpAddress,
            SortColumn::IpAddress => SortColumn::ClockIdentity,
            SortColumn::ClockIdentity => SortColumn::State,
            SortColumn::State => SortColumn::LastSeen,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            SortColumn::ClockIdentity => "Clock Identity",
            SortColumn::IpAddress => "IP Address",
            SortColumn::State => "State",
            SortColumn::Domain => "Domain",
            SortColumn::Priority => "Priority",
            SortColumn::ClockClass => "Clock Class",
            SortColumn::SelectedTransmitter => "Selected Transmitter",
            SortColumn::MessageCount => "Msg Count",
            SortColumn::LastSeen => "Last Seen",
        }
    }
}

pub struct App {
    pub state: AppState,
    pub update_interval: Duration,
    pub debug: bool,
    pub ptp_tracker: PtpTracker,
    pub last_update: Instant,
    pub selected_index: usize,
    pub host_scroll_offset: usize,
    pub visible_height: usize,
    pub show_help: bool,
    pub theme: crate::themes::Theme,

    pub packet_scroll_offset: usize,
    pub max_packet_history: usize,
    pub packet_history_expanded: bool,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
    pub selected_host_id: Option<ClockIdentity>,
    pub paused: bool,
}

impl App {
    pub fn new(
        update_interval: Duration,
        debug: bool,
        theme_name: crate::themes::ThemeName,
        raw_socket_receiver: crate::socket::RawSocketReceiver,
    ) -> Result<Self> {
        let ptp_tracker = PtpTracker::new(raw_socket_receiver)?;
        let theme = crate::themes::Theme::new(theme_name);

        let mut app = Self {
            state: AppState::Running,
            update_interval,
            debug,
            ptp_tracker,
            last_update: Instant::now(),
            selected_index: 0,
            host_scroll_offset: 0,
            visible_height: 20,
            show_help: false,
            theme,
            packet_scroll_offset: 0,
            max_packet_history: 1000,
            packet_history_expanded: false,
            sort_column: SortColumn::ClockIdentity,
            sort_ascending: true,
            selected_host_id: None,
            paused: false,
        };

        // Set the max packet history on the tracker
        app.ptp_tracker
            .set_max_packet_history(app.max_packet_history);

        Ok(app)
    }

    pub async fn run(&mut self) -> Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Main application loop
        let result = self.run_app(&mut terminal).await;

        // Restore terminal
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        result
    }

    async fn run_app<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        let mut last_tick = Instant::now();

        loop {
            // Draw the UI
            terminal.draw(|f| ui(f, self))?;

            // Handle timeout for updates
            let timeout = self.update_interval.saturating_sub(last_tick.elapsed());

            // Check for events
            if event::poll(timeout)? {
                match event::read()? {
                    Event::Key(key) => {
                        if let Err(_e) = self.handle_key_event(key.code).await {
                            self.state = AppState::Quitting;
                            break;
                        }
                    }
                    Event::Resize(_, _) => {}
                    _ => {}
                }
            }

            // Update data if enough time has passed
            if last_tick.elapsed() >= self.update_interval {
                if let Err(_e) = self.update_data().await {
                    self.state = AppState::Quitting;
                    break;
                }
                last_tick = Instant::now();
            }

            // Check if we should quit
            if self.state == AppState::Quitting {
                break;
            }

            // Small delay to prevent busy waiting
            time::sleep(Duration::from_millis(10)).await;
        }

        Ok(())
    }

    async fn handle_key_event(&mut self, key_code: KeyCode) -> Result<()> {
        match key_code {
            KeyCode::Char('q') => {
                self.state = AppState::Quitting;
            }
            KeyCode::Esc => {
                if self.show_help {
                    self.show_help = false;
                } else {
                    self.state = AppState::Quitting;
                }
            }
            KeyCode::Char('h') | KeyCode::F(1) => {
                self.show_help = !self.show_help;
            }
            KeyCode::Char('r') => {
                self.update_data().await?;
            }
            KeyCode::Char('\x0C') => {
                // Ctrl+L - refresh/redraw screen (standard terminal convention)
                // Force a complete redraw by updating data and clearing screen state
                self.update_data().await?;
            }
            KeyCode::Char('c') => {
                self.ptp_tracker.clear_hosts();
                self.ptp_tracker.clear_all_packet_histories();
                self.selected_index = 0;
                self.selected_host_id = None;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection_up();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection_down();
            }
            KeyCode::PageUp => {
                self.move_selection_page_up();
            }
            KeyCode::PageDown => {
                self.move_selection_page_down(self.visible_height);
            }
            KeyCode::Home => {
                self.move_selection_to_top();
            }
            KeyCode::End => {
                self.move_selection_to_bottom(self.visible_height);
            }
            KeyCode::Char('d') => {
                self.debug = !self.debug;
            }
            KeyCode::Char('p') => {
                self.paused = !self.paused;
            }
            KeyCode::Char('w') => {
                self.toggle_auto_scroll();
            }
            KeyCode::Char('e') => {
                self.packet_history_expanded = !self.packet_history_expanded;
            }
            KeyCode::Char('s') => {
                self.cycle_sort_column();
            }
            KeyCode::Char('S') => {
                self.toggle_sort_direction();
            }
            KeyCode::Char('a') => {
                self.cycle_sort_column_previous();
            }
            KeyCode::Char('t') => {
                // Restore selection in the new view mode
                self.restore_host_selection();
            }
            KeyCode::Char('x') => {
                self.clear_packet_history();
            }
            _ => {
                // Other keys - no action needed
            }
        }
        Ok(())
    }

    pub async fn update_data(&mut self) -> Result<()> {
        // Skip network scanning if paused
        if self.paused {
            return Ok(());
        }

        self.ptp_tracker.scan_network().await;
        // Restore host selection to maintain stability when list changes
        self.restore_host_selection();
        self.last_update = Instant::now();

        Ok(())
    }

    /// Helper method to update the selected host ID and reset packet scroll offset
    fn update_selected_host(&mut self, index: usize) {
        self.packet_scroll_offset = 0;
        if let Some(host) = self.get_hosts().get(index) {
            self.selected_host_id = Some(host.clock_identity.clone());
        } else {
            // If index is out of bounds, clear selection
            self.selected_host_id = None;
        }
    }

    fn move_selection_up(&mut self) {
        let total_hosts = self.ptp_tracker.get_hosts().len();

        if total_hosts > 0 && self.selected_index > 0 {
            self.selected_index -= 1;
            self.update_selected_host(self.selected_index);
            // Scroll up immediately if we're at the top of the visible area
            if self.selected_index < self.host_scroll_offset {
                self.host_scroll_offset = self.selected_index;
            }
        }
    }

    fn move_selection_down(&mut self) {
        let total_hosts = self.ptp_tracker.get_hosts().len();

        if total_hosts > 0 && self.selected_index < total_hosts - 1 {
            self.selected_index += 1;
            self.update_selected_host(self.selected_index);
            // Scroll down immediately if we're at the bottom of the visible area
            let last_visible_index =
                self.host_scroll_offset + self.visible_height.saturating_sub(1);
            if self.selected_index > last_visible_index {
                let max_scroll_offset = if total_hosts > self.visible_height {
                    total_hosts - self.visible_height
                } else {
                    0
                };
                self.host_scroll_offset = (self.selected_index + 1)
                    .saturating_sub(self.visible_height)
                    .min(max_scroll_offset);
            }
        }
    }

    pub fn ensure_host_visible(&mut self, visible_height: usize) {
        let total_hosts = self.ptp_tracker.get_hosts().len();

        if total_hosts == 0 || visible_height == 0 {
            return;
        }

        // Ensure selection is within bounds
        if self.selected_index >= total_hosts {
            self.selected_index = total_hosts.saturating_sub(1);
        }

        // Calculate the maximum scroll offset that still shows content
        // For N hosts and V visible rows, max scroll is N-V (but never negative)
        let max_scroll_offset = if total_hosts > visible_height {
            total_hosts - visible_height
        } else {
            0
        };

        // Ensure scroll offset doesn't exceed the maximum
        if self.host_scroll_offset > max_scroll_offset {
            self.host_scroll_offset = max_scroll_offset;
        }

        // Scroll down if selected item is below visible area
        let last_visible_index = self.host_scroll_offset + visible_height - 1;
        if self.selected_index > last_visible_index {
            // Keep selected item at the bottom of visible area
            self.host_scroll_offset = self.selected_index.saturating_sub(visible_height - 1);
            // But don't exceed max scroll offset
            self.host_scroll_offset = self.host_scroll_offset.min(max_scroll_offset);
        }

        // Scroll up if selected item is above visible area
        if self.selected_index < self.host_scroll_offset {
            self.host_scroll_offset = self.selected_index;
        }
    }

    pub fn get_host_scroll_offset(&self) -> usize {
        self.host_scroll_offset
    }

    pub fn set_visible_height(&mut self, visible_height: usize) {
        self.visible_height = visible_height;
    }

    pub fn move_selection_page_up(&mut self) {
        if self.ptp_tracker.get_hosts().len() == 0 {
            return;
        }

        // Move up by 10 items or to the beginning
        let old_index = self.selected_index;
        self.selected_index = self.selected_index.saturating_sub(10);

        if self.selected_index != old_index {
            self.update_selected_host(self.selected_index);
            self.ensure_host_visible(20);
        }
    }

    pub fn move_selection_page_down(&mut self, visible_height: usize) {
        let total_hosts = self.ptp_tracker.get_hosts().len();

        if total_hosts == 0 || visible_height == 0 {
            return;
        }

        // Move down by 10 items or to the end
        let old_index = self.selected_index;
        self.selected_index = (self.selected_index + 10).min(total_hosts - 1);

        if self.selected_index != old_index {
            self.update_selected_host(self.selected_index);
        }

        // Adjust scroll to keep selection in view
        let last_visible_index = self.host_scroll_offset + visible_height - 1;
        if self.selected_index > last_visible_index {
            let max_scroll_offset = if total_hosts > visible_height {
                total_hosts - visible_height
            } else {
                0
            };
            self.host_scroll_offset = self
                .selected_index
                .saturating_sub(visible_height - 1)
                .min(max_scroll_offset);
        }
    }

    pub fn move_selection_to_top(&mut self) {
        self.selected_index = 0;
        self.host_scroll_offset = 0;
        self.update_selected_host(0);
    }

    pub fn move_selection_to_bottom(&mut self, visible_height: usize) {
        let total_hosts = self.ptp_tracker.get_hosts().len();

        if total_hosts > 0 {
            self.selected_index = total_hosts - 1;
            self.update_selected_host(self.selected_index);

            // Set scroll to show the bottom of the list
            let max_scroll_offset = if total_hosts > visible_height {
                total_hosts - visible_height
            } else {
                0
            };
            self.host_scroll_offset = max_scroll_offset;
        }
    }

    pub fn get_hosts(&self) -> Vec<&PtpHost> {
        let mut hosts = self.ptp_tracker.get_hosts();

        // Sort hosts based on current sort column
        hosts.sort_by(|a, b| {
            let comparison = match self.sort_column {
                SortColumn::ClockIdentity => a.clock_identity.cmp(&b.clock_identity),
                SortColumn::IpAddress => {
                    let a_ip = a.get_primary_ip();
                    let b_ip = b.get_primary_ip();
                    a_ip.cmp(&b_ip)
                }
                SortColumn::State => {
                    let a_state_order = match &a.state {
                        PtpHostState::TimeTransmitter(_) => 0,
                        PtpHostState::TimeReceiver(_) => 1,
                        PtpHostState::Listening => 2,
                    };
                    let b_state_order = match &b.state {
                        PtpHostState::TimeTransmitter(_) => 0,
                        PtpHostState::TimeReceiver(_) => 1,
                        PtpHostState::Listening => 2,
                    };
                    a_state_order.cmp(&b_state_order)
                }
                SortColumn::Domain => a.domain_number.cmp(&b.domain_number),
                SortColumn::Priority => {
                    let a_priority = match &a.state {
                        PtpHostState::TimeTransmitter(s) => s.priority1.unwrap_or(255),
                        _ => 255,
                    };
                    let b_priority = match &b.state {
                        PtpHostState::TimeTransmitter(s) => s.priority1.unwrap_or(255),
                        _ => 255,
                    };
                    a_priority.cmp(&b_priority)
                }
                SortColumn::ClockClass => {
                    let a_clock_class = match &a.state {
                        PtpHostState::TimeTransmitter(s) => {
                            s.clock_class.map_or(255, |c| c.class())
                        }
                        _ => 255,
                    };
                    let b_clock_class = match &b.state {
                        PtpHostState::TimeTransmitter(s) => {
                            s.clock_class.map_or(255, |c| c.class())
                        }
                        _ => 255,
                    };
                    a_clock_class.cmp(&b_clock_class)
                }
                SortColumn::SelectedTransmitter => {
                    let a = match &a.state {
                        PtpHostState::TimeReceiver(s) => {
                            s.selected_transmitter_identity.unwrap_or_default()
                        }
                        _ => ClockIdentity::default(),
                    };

                    let b = match &b.state {
                        PtpHostState::TimeReceiver(s) => {
                            s.selected_transmitter_identity.unwrap_or_default()
                        }
                        _ => ClockIdentity::default(),
                    };

                    a.cmp(&b)
                }
                SortColumn::MessageCount => a
                    .total_messages_sent_count
                    .cmp(&b.total_messages_sent_count),
                SortColumn::LastSeen => a.last_seen.cmp(&b.last_seen),
            };

            if self.sort_ascending {
                comparison
            } else {
                comparison.reverse()
            }
        });

        hosts
    }

    pub fn get_selected_index(&self) -> usize {
        self.selected_index
    }

    pub fn get_sort_column(&self) -> &SortColumn {
        &self.sort_column
    }

    pub fn cycle_sort_column(&mut self) {
        self.sort_column = self.sort_column.next();
        self.restore_host_selection();
    }

    pub fn cycle_sort_column_previous(&mut self) {
        self.sort_column = self.sort_column.previous();
        self.restore_host_selection();
    }

    pub fn toggle_sort_direction(&mut self) {
        self.sort_ascending = !self.sort_ascending;
        self.restore_host_selection();
    }

    pub fn is_sort_ascending(&self) -> bool {
        self.sort_ascending
    }

    pub fn get_packet_history(&self) -> Vec<ProcessedPacket> {
        // Return packets from the currently selected host
        if let Some(ref selected_host_id) = self.selected_host_id {
            if let Some(history) = self.ptp_tracker.get_host_packet_history(*selected_host_id) {
                return history;
            }
        }
        Vec::new()
    }

    pub fn get_packet_scroll_offset(&self) -> usize {
        self.packet_scroll_offset
    }

    fn find_host_index(&self, clock_identity: ClockIdentity) -> Option<usize> {
        self.get_hosts()
            .iter()
            .position(|host| host.clock_identity == clock_identity)
    }

    fn get_host_count(&self) -> usize {
        self.ptp_tracker.get_hosts().len()
    }

    /// Helper method to clamp index within valid bounds and update selection
    fn clamp_and_update_selection(&mut self, index: usize) {
        let host_count = self.get_host_count();
        let clamped_index = if host_count == 0 {
            0
        } else {
            index.min(host_count - 1)
        };

        self.selected_index = clamped_index;
        if host_count > 0 {
            self.update_selected_host(clamped_index);
        }
    }

    fn restore_host_selection(&mut self) {
        // If we have a stored host ID, try to find it in the current list
        if let Some(ref stored_host_id) = self.selected_host_id.clone() {
            if let Some(found_index) = self.find_host_index(*stored_host_id) {
                // Found the stored host, select it
                self.selected_index = found_index;
                self.ensure_host_visible(20);
                return;
            }
        }

        // Either no stored host ID, or stored host not found - clamp current index
        self.clamp_and_update_selection(self.selected_index);
    }

    pub fn clear_packet_history(&mut self) {
        if let Some(ref selected_host_id) = self.selected_host_id {
            self.ptp_tracker
                .clear_host_packet_history(*selected_host_id);
        } else {
            // If no host is selected, clear all histories
            self.ptp_tracker.clear_all_packet_histories();
        }
    }

    pub fn toggle_auto_scroll(&mut self) {
        // This method is kept for compatibility but does nothing
        // since packets are now non-interactive
    }

    pub fn is_packet_history_expanded(&self) -> bool {
        self.packet_history_expanded
    }
}
