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

use crate::{
    events::EventHandler,
    ptp::{PtpHost, PtpMessageType, PtpState, PtpTracker},
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
    SelectedLeader,
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
            SortColumn::ClockClass => SortColumn::SelectedLeader,
            SortColumn::SelectedLeader => SortColumn::MessageCount,
            SortColumn::MessageCount => SortColumn::LastSeen,
            SortColumn::LastSeen => SortColumn::State,
        }
    }

    pub fn previous(&self) -> Self {
        match self {
            SortColumn::LastSeen => SortColumn::MessageCount,
            SortColumn::MessageCount => SortColumn::SelectedLeader,
            SortColumn::SelectedLeader => SortColumn::ClockClass,
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
            SortColumn::SelectedLeader => "Selected Leader",
            SortColumn::MessageCount => "Msg Count",
            SortColumn::LastSeen => "Last Seen",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: Instant,
    pub source_ip: String,
    pub source_port: u16,
    pub interface: String,
    pub version: u8,
    pub message_type: PtpMessageType,
    pub message_length: u16,
    pub clock_identity: String,
    pub domain_number: u8,
    pub sequence_id: u16,
    pub flags: [u8; 2],
    pub correction_field: i64,
    pub log_message_interval: i8,
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

    pub packet_history: Vec<PacketInfo>,
    pub packet_scroll_offset: usize,
    pub max_packet_history: usize,
    pub packet_history_expanded: bool,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
    pub selected_host_id: Option<String>,
}

impl App {
    pub fn new(
        update_interval: Duration,
        debug: bool,
        theme_name: crate::themes::ThemeName,
        event_socket: tokio::net::UdpSocket,
        general_socket: tokio::net::UdpSocket,
        interfaces: Vec<(String, std::net::Ipv4Addr)>,
    ) -> Result<Self> {
        let ptp_tracker = PtpTracker::new(event_socket, general_socket, interfaces)?;
        let theme = crate::themes::Theme::new(theme_name);

        Ok(Self {
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
            packet_history: Vec::new(),
            packet_scroll_offset: 0,
            max_packet_history: 1000,
            packet_history_expanded: false,
            sort_column: SortColumn::State,
            sort_ascending: false,
            selected_host_id: None,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Create event handler
        let mut event_handler = EventHandler::new();

        // Main application loop
        let result = self.run_app(&mut terminal, &mut event_handler).await;

        // Restore terminal
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        result
    }

    async fn run_app<B: Backend>(
        &mut self,
        terminal: &mut Terminal<B>,
        _event_handler: &mut EventHandler,
    ) -> Result<()> {
        let mut last_tick = Instant::now();

        loop {
            // Ensure host selection is consistent before drawing UI
            self.restore_host_selection();

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
            KeyCode::Char('c') => {
                self.ptp_tracker.clear_hosts();
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
                self.clear_packet_history();
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

            _ => {
                // Other keys - no action needed
            }
        }
        Ok(())
    }

    pub async fn update_data(&mut self) -> Result<()> {
        // Update the stored selected host ID from current selection
        if let Some(host) = self.get_hosts().get(self.selected_index) {
            self.selected_host_id = Some(host.clock_identity.clone());
        }

        let processed_packets = self.ptp_tracker.scan_network().await?;

        // Add packets to history
        for packet in processed_packets {
            let packet_info = PacketInfo {
                timestamp: packet.timestamp,
                source_ip: packet.source_ip.to_string(),
                source_port: packet.source_port,
                interface: packet.interface,
                version: packet.version,
                message_type: packet.message_type,
                message_length: packet.message_length,
                clock_identity: packet.clock_identity,
                domain_number: packet.domain_number,
                sequence_id: packet.sequence_id,
                flags: packet.flags,
                correction_field: packet.correction_field,
                log_message_interval: packet.log_message_interval,
            };
            self.add_packet(packet_info);
        }

        // Always restore host selection based on stored ID
        self.restore_host_selection();

        self.last_update = Instant::now();
        Ok(())
    }

    fn move_selection_up(&mut self) {
        let hosts = self.ptp_tracker.get_hosts();
        if !hosts.is_empty() && self.selected_index > 0 {
            self.selected_index -= 1;
            // Update stored host ID
            if let Some(host) = self.get_hosts().get(self.selected_index) {
                self.selected_host_id = Some(host.clock_identity.clone());
            }
            // Scroll up immediately if we're at the top of the visible area
            if self.selected_index < self.host_scroll_offset {
                self.host_scroll_offset = self.selected_index;
            }
        }
    }

    fn move_selection_down(&mut self) {
        let hosts = self.ptp_tracker.get_hosts();
        if !hosts.is_empty() && self.selected_index < hosts.len() - 1 {
            self.selected_index += 1;
            // Update stored host ID
            if let Some(host) = self.get_hosts().get(self.selected_index) {
                self.selected_host_id = Some(host.clock_identity.clone());
            }
            // Scroll down immediately if we're at the bottom of the visible area
            let last_visible_index =
                self.host_scroll_offset + self.visible_height.saturating_sub(1);
            if self.selected_index > last_visible_index {
                let max_scroll_offset = if hosts.len() > self.visible_height {
                    hosts.len() - self.visible_height
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
        let hosts = self.ptp_tracker.get_hosts();
        if hosts.is_empty() || visible_height == 0 {
            return;
        }

        // Ensure selection is within bounds
        if self.selected_index >= hosts.len() {
            self.selected_index = hosts.len().saturating_sub(1);
        }

        // Calculate the maximum scroll offset that still shows content
        // For N hosts and V visible rows, max scroll is N-V (but never negative)
        let max_scroll_offset = if hosts.len() > visible_height {
            hosts.len() - visible_height
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
        let hosts = self.ptp_tracker.get_hosts();
        if hosts.is_empty() {
            return;
        }

        // Move up by 10 items or to the beginning
        self.selected_index = self.selected_index.saturating_sub(10);
        // Update stored host ID
        if let Some(host) = self.get_hosts().get(self.selected_index) {
            self.selected_host_id = Some(host.clock_identity.clone());
        }
        // Adjust scroll to keep selection in view
        if self.selected_index < self.host_scroll_offset {
            self.host_scroll_offset = self.selected_index;
        }
    }

    pub fn move_selection_page_down(&mut self, visible_height: usize) {
        let hosts = self.ptp_tracker.get_hosts();
        if hosts.is_empty() || visible_height == 0 {
            return;
        }

        // Move down by 10 items or to the end
        let max_index = hosts.len().saturating_sub(1);
        self.selected_index = (self.selected_index + 10).min(max_index);

        // Update stored host ID
        if let Some(host) = self.get_hosts().get(self.selected_index) {
            self.selected_host_id = Some(host.clock_identity.clone());
        }

        // Adjust scroll to keep selection in view
        let last_visible_index = self.host_scroll_offset + visible_height - 1;
        if self.selected_index > last_visible_index {
            let max_scroll_offset = if hosts.len() > visible_height {
                hosts.len() - visible_height
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
        // Update stored host ID
        if let Some(host) = self.get_hosts().get(0) {
            self.selected_host_id = Some(host.clock_identity.clone());
        }
    }

    pub fn move_selection_to_bottom(&mut self, visible_height: usize) {
        let hosts = self.ptp_tracker.get_hosts();
        if !hosts.is_empty() && visible_height > 0 {
            self.selected_index = hosts.len().saturating_sub(1);
            // Update stored host ID
            if let Some(host) = hosts.get(self.selected_index) {
                self.selected_host_id = Some(host.clock_identity.clone());
            }
            // Scroll to show the bottom, with selected item at the bottom of visible area
            let max_scroll_offset = if hosts.len() > visible_height {
                hosts.len() - visible_height
            } else {
                0
            };
            self.host_scroll_offset = max_scroll_offset;
        }
    }

    fn select_current_host(&mut self) {
        let hosts = self.ptp_tracker.get_hosts();
        if let Some(_host) = hosts.get(self.selected_index) {
            // TODO: Implement detailed host view or actions
            // Host selected - no action needed for now
        }
    }

    pub fn get_hosts(&self) -> Vec<&PtpHost> {
        let mut hosts = self.ptp_tracker.get_hosts();

        // Sort hosts based on current sort column
        hosts.sort_by(|a, b| {
            let comparison = match self.sort_column {
                SortColumn::ClockIdentity => a.clock_identity.cmp(&b.clock_identity),
                SortColumn::IpAddress => {
                    let a_ip = a
                        .get_primary_ip()
                        .map(|ip| ip.to_string())
                        .unwrap_or_default();
                    let b_ip = b
                        .get_primary_ip()
                        .map(|ip| ip.to_string())
                        .unwrap_or_default();
                    a_ip.cmp(&b_ip)
                }
                SortColumn::State => {
                    let a_state_order = match a.state {
                        PtpState::Leader => 0,
                        PtpState::Follower => 1,
                        PtpState::Passive => 2,
                        PtpState::Listening => 3,
                        _ => 4,
                    };
                    let b_state_order = match b.state {
                        PtpState::Leader => 0,
                        PtpState::Follower => 1,
                        PtpState::Passive => 2,
                        PtpState::Listening => 3,
                        _ => 4,
                    };
                    a_state_order.cmp(&b_state_order)
                }
                SortColumn::Domain => a.domain_number.cmp(&b.domain_number),
                SortColumn::Priority => a.priority1.cmp(&b.priority1),
                SortColumn::ClockClass => a.clock_class.cmp(&b.clock_class),
                SortColumn::SelectedLeader => {
                    let a_leader = a.selected_leader_id.as_deref().unwrap_or("");
                    let b_leader = b.selected_leader_id.as_deref().unwrap_or("");
                    a_leader.cmp(b_leader)
                }
                SortColumn::MessageCount => a.total_message_count.cmp(&b.total_message_count),
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
        // Store currently selected host before sorting changes
        self.sort_column = self.sort_column.next();

        // Restore selection after sorting
        self.restore_host_selection();
    }

    pub fn cycle_sort_column_previous(&mut self) {
        // Store currently selected host before sorting changes
        self.sort_column = self.sort_column.previous();

        // Restore selection after sorting
        self.restore_host_selection();
    }

    pub fn toggle_sort_direction(&mut self) {
        // Store currently selected host before sorting changes
        self.sort_ascending = !self.sort_ascending;

        // Restore selection after sorting
        self.restore_host_selection();
    }

    pub fn is_sort_ascending(&self) -> bool {
        self.sort_ascending
    }

    pub fn add_packet(&mut self, packet: PacketInfo) {
        self.packet_history.push(packet);

        // Limit packet history size
        if self.packet_history.len() > self.max_packet_history {
            self.packet_history.remove(0);
        }
    }

    pub fn get_packet_history(&self) -> &[PacketInfo] {
        &self.packet_history
    }

    pub fn get_packet_scroll_offset(&self) -> usize {
        self.packet_scroll_offset
    }

    fn restore_host_selection(&mut self) {
        // If we have a stored host ID, try to find it in the current list
        if let Some(ref stored_host_id) = self.selected_host_id.clone() {
            let hosts = self.get_hosts();

            // Try to find the host by clock identity
            for (index, host) in hosts.iter().enumerate() {
                if host.clock_identity == *stored_host_id {
                    self.selected_index = index;
                    self.ensure_host_visible(20);
                    return;
                }
            }

            // If we can't find the stored host, it might have been removed
            // Keep the current index but ensure it's within bounds
            let hosts_len = hosts.len();
            let new_index = if self.selected_index >= hosts_len {
                hosts_len.saturating_sub(1)
            } else {
                self.selected_index
            };

            // Get the host at the new index for updating stored ID
            let new_host_id = hosts.get(new_index).map(|h| h.clock_identity.clone());

            // Now update the fields
            self.selected_index = new_index;
            self.selected_host_id = new_host_id;
        } else {
            // No stored selection, ensure current index is valid
            let hosts = self.get_hosts();
            let hosts_len = hosts.len();
            let new_index = if self.selected_index >= hosts_len {
                hosts_len.saturating_sub(1)
            } else {
                self.selected_index
            };

            // Get the host at the new index for storing ID
            let new_host_id = hosts.get(new_index).map(|h| h.clock_identity.clone());

            // Update the fields
            self.selected_index = new_index;
            self.selected_host_id = new_host_id;
        }
    }

    pub fn clear_packet_history(&mut self) {
        self.packet_history.clear();
    }

    pub fn toggle_auto_scroll(&mut self) {
        // This method is kept for compatibility but does nothing
        // since packets are now non-interactive
    }

    pub fn is_packet_history_expanded(&self) -> bool {
        self.packet_history_expanded
    }
}
