use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::{Backend, CrosstermBackend},
    layout::Rect,
};
use std::{
    io,
    time::{Duration, Instant},
};
use tokio::time;

use crate::types::{ClockIdentity, ParsedPacket};

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
pub enum ActiveView {
    HostTable,
    HostDetails,
    PacketHistory,
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
    Vendor,
}

impl SortColumn {
    pub fn next(&self) -> Self {
        match self {
            SortColumn::State => SortColumn::ClockIdentity,
            SortColumn::ClockIdentity => SortColumn::IpAddress,
            SortColumn::IpAddress => SortColumn::Vendor,
            SortColumn::Vendor => SortColumn::Domain,
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
            SortColumn::Domain => SortColumn::Vendor,
            SortColumn::Vendor => SortColumn::IpAddress,
            SortColumn::IpAddress => SortColumn::ClockIdentity,
            SortColumn::ClockIdentity => SortColumn::State,
            SortColumn::State => SortColumn::LastSeen,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            SortColumn::State => "State",
            SortColumn::ClockIdentity => "Clock Identity",
            SortColumn::IpAddress => "IP Address",
            SortColumn::Vendor => "Vendor",
            SortColumn::Domain => "Domain",
            SortColumn::Priority => "Priority",
            SortColumn::ClockClass => "Clock Class",
            SortColumn::SelectedTransmitter => "Selected Transmitter",
            SortColumn::MessageCount => "Msg Count",
            SortColumn::LastSeen => "Last Seen",
        }
    }
}

#[derive(Clone)]
pub struct TreeNode {
    pub host: PtpHost,
    pub children: Vec<TreeNode>,
    pub depth: usize,
    pub is_primary_transmitter: bool,
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
    pub tree_view_mode: bool,
    pub active_view: ActiveView,
    pub selected_packet_index: usize,
    pub auto_scroll_packets: bool,
    pub visible_packet_height: usize,
    pub show_packet_modal: bool,
    pub modal_packet: Option<ParsedPacket>,
    pub modal_scroll_offset: usize,
    pub modal_visible_height: usize,
    pub force_redraw: bool,
    pub host_details_scroll_offset: usize,
    pub host_details_visible_height: usize,
    pub host_selection_changed: bool,
    pub packet_selection_changed: bool,
}

impl App {
    pub fn new(
        update_interval: Duration,
        debug: bool,
        theme_name: crate::themes::ThemeName,
        raw_socket_receiver: crate::source::RawSocketReceiver,
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
            tree_view_mode: false,
            active_view: ActiveView::HostTable,
            selected_packet_index: 0,
            auto_scroll_packets: true,
            visible_packet_height: 8,
            show_packet_modal: false,
            modal_packet: None,
            modal_scroll_offset: 0,
            modal_visible_height: 10,
            force_redraw: false,
            host_details_scroll_offset: 0,
            host_details_visible_height: 10,
            host_selection_changed: true,
            packet_selection_changed: true,
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
            // Handle forced redraw (like Ctrl+L)
            if self.force_redraw {
                let size = terminal.size()?;
                terminal.resize(Rect::new(0, 0, size.width, size.height))?;
                terminal.clear()?;
                self.force_redraw = false;
            }

            // Draw the UI
            terminal.draw(|f| ui(f, self))?;

            // Handle timeout for updates
            let timeout = self.update_interval.saturating_sub(last_tick.elapsed());

            // Check for events
            if event::poll(timeout)? {
                match event::read()? {
                    Event::Key(key) => {
                        if let Err(_e) = self.handle_key_event_with_modifiers(key).await {
                            self.state = AppState::Quitting;
                            break;
                        }
                    }
                    Event::Resize(_, _) => {
                        // Terminal resize automatically triggers full redraw
                        let size = terminal.size()?;
                        terminal.resize(Rect::new(0, 0, size.width, size.height))?;
                    }
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

    async fn handle_key_event_with_modifiers(
        &mut self,
        key: crossterm::event::KeyEvent,
    ) -> Result<()> {
        self.handle_key_event(key.code, key.modifiers).await
    }

    async fn handle_key_event(
        &mut self,
        key_code: KeyCode,
        modifiers: crossterm::event::KeyModifiers,
    ) -> Result<()> {
        match key_code {
            KeyCode::Tab => {
                self.active_view = match self.active_view {
                    ActiveView::HostTable => ActiveView::HostDetails,
                    ActiveView::HostDetails => ActiveView::PacketHistory,
                    ActiveView::PacketHistory => ActiveView::HostTable,
                };
                // When switching to packet history, preserve selection unless it's invalid
                if matches!(self.active_view, ActiveView::PacketHistory) {
                    let packet_count = self.get_packet_history().len();
                    if packet_count > 0 {
                        // Only reset to most recent if current selection is out of bounds
                        if self.selected_packet_index >= packet_count {
                            self.selected_packet_index = packet_count - 1;
                            self.packet_selection_changed = true;
                        }
                        // If we have a valid selection, keep it but ensure it's visible
                        if !self.packet_selection_changed {
                            self.packet_selection_changed = true; // Ensure visibility check
                        }
                    } else {
                        self.selected_packet_index = 0;
                    }
                    self.auto_scroll_packets = false;
                }
                // Don't automatically enable auto-scroll when leaving PacketHistory
                // This preserves the user's packet selection when they TAB back
            }
            KeyCode::Char('q') => {
                self.state = AppState::Quitting;
            }
            KeyCode::Esc => {
                if self.show_packet_modal {
                    self.show_packet_modal = false;
                    self.modal_packet = None;
                    self.modal_scroll_offset = 0;
                    self.modal_visible_height = 10;
                } else if self.show_help {
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
            KeyCode::Char('\x0C') | KeyCode::Char('l')
                if modifiers.contains(crossterm::event::KeyModifiers::CONTROL) =>
            {
                // Ctrl+L - refresh/redraw screen (standard terminal convention)
                // Force a complete refresh like terminal resize does
                self.update_data().await?;
                self.force_redraw = true;
            }
            KeyCode::Char('c') => {
                self.ptp_tracker.clear_hosts();
                self.ptp_tracker.clear_all_packet_histories();
                self.selected_index = 0;
                self.selected_host_id = None;
                self.host_selection_changed = true;
                self.packet_selection_changed = true;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.show_packet_modal {
                    self.scroll_modal_up();
                } else {
                    match self.active_view {
                        ActiveView::HostTable => self.move_selection_up(),
                        ActiveView::HostDetails => self.scroll_host_details_up(),
                        ActiveView::PacketHistory => self.move_packet_selection_up(),
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.show_packet_modal {
                    self.scroll_modal_down();
                } else {
                    match self.active_view {
                        ActiveView::HostTable => self.move_selection_down(),
                        ActiveView::HostDetails => self.scroll_host_details_down(),
                        ActiveView::PacketHistory => self.move_packet_selection_down(),
                    }
                }
            }
            KeyCode::PageUp => {
                if self.show_packet_modal {
                    self.scroll_modal_page_up(self.modal_visible_height);
                } else {
                    match self.active_view {
                        ActiveView::HostTable => self.move_selection_page_up(),
                        ActiveView::HostDetails => self.scroll_host_details_page_up(),
                        ActiveView::PacketHistory => self.move_packet_selection_page_up(),
                    }
                }
            }
            KeyCode::PageDown => {
                if self.show_packet_modal {
                    self.scroll_modal_page_down(self.modal_visible_height);
                } else {
                    match self.active_view {
                        ActiveView::HostTable => self.move_selection_page_down(self.visible_height),
                        ActiveView::HostDetails => self.scroll_host_details_page_down(),
                        ActiveView::PacketHistory => self.move_packet_selection_page_down(),
                    }
                }
            }
            KeyCode::Char(' ') => {
                if self.show_packet_modal {
                    self.scroll_modal_page_down(self.modal_visible_height);
                } else {
                    // Space does nothing when modal is not open
                }
            }
            KeyCode::Home => {
                if self.show_packet_modal {
                    self.scroll_modal_to_top();
                } else {
                    match self.active_view {
                        ActiveView::HostTable => self.move_selection_to_top(),
                        ActiveView::HostDetails => self.scroll_host_details_to_top(),
                        ActiveView::PacketHistory => self.move_packet_selection_to_top(),
                    }
                }
            }
            KeyCode::End => {
                if self.show_packet_modal {
                    self.scroll_modal_to_bottom();
                } else {
                    match self.active_view {
                        ActiveView::HostTable => self.move_selection_to_bottom(self.visible_height),
                        ActiveView::HostDetails => self.scroll_host_details_to_bottom(),
                        ActiveView::PacketHistory => self.move_packet_selection_to_bottom(),
                    }
                }
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
                // Toggle tree view mode
                self.tree_view_mode = !self.tree_view_mode;
                // Restore selection in the new view mode
                self.restore_host_selection();
            }
            KeyCode::Char('x') => {
                self.clear_packet_history();
            }
            KeyCode::Enter => {
                if self.show_packet_modal {
                    // When modal is open, ENTER acts like cursor down
                    self.scroll_modal_down();
                } else if matches!(self.active_view, ActiveView::PacketHistory) {
                    let packet_count = self.get_packet_history().len();
                    if packet_count > 0
                        && self.selected_packet_index < packet_count
                        && let Some(packet) = self.get_selected_packet()
                    {
                        self.modal_packet = Some(packet);
                        self.show_packet_modal = true;
                        self.modal_scroll_offset = 0;
                    }
                }
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
        // Get the host clock identity based on current view mode
        let host_clock_identity = if self.tree_view_mode {
            // In tree mode, get the clock identity from the tree structure
            self.get_tree_host_clock_identity_at_index(index)
        } else {
            // In flat mode, use the flat host list
            self.get_hosts().get(index).map(|host| host.clock_identity)
        };

        let new_host_id = host_clock_identity;

        // Check if the host actually changed before updating
        let host_changed = self.selected_host_id != new_host_id;

        if host_changed {
            self.packet_scroll_offset = 0;
            self.host_details_scroll_offset = 0;
            self.host_selection_changed = true;
            self.packet_selection_changed = true;
        }

        self.selected_index = index;
        self.selected_host_id = new_host_id;

        // Reset to most recent packet when host changes (after host ID is updated)
        if host_changed {
            let packet_count = self.get_packet_history().len();
            if packet_count > 0 {
                self.selected_packet_index = packet_count - 1;
            } else {
                self.selected_packet_index = 0;
            }
        }
    }

    /// Get the clock identity of the host at the given index in tree view
    fn get_tree_host_clock_identity_at_index(&self, index: usize) -> Option<ClockIdentity> {
        let tree_nodes = self.get_hosts_tree();
        let mut current_index = 0;

        fn find_at_index(
            nodes: &[TreeNode],
            target_index: usize,
            current_index: &mut usize,
        ) -> Option<ClockIdentity> {
            for node in nodes {
                if *current_index == target_index {
                    return Some(node.host.clock_identity);
                }
                *current_index += 1;

                if let Some(result) = find_at_index(&node.children, target_index, current_index) {
                    return Some(result);
                }
            }
            None
        }

        find_at_index(&tree_nodes, index, &mut current_index)
    }

    /// Get the count of items in the current view (tree or flat)
    fn get_tree_item_count(&self) -> usize {
        let tree_nodes = self.get_hosts_tree();

        fn count_nodes(nodes: &[TreeNode]) -> usize {
            let mut count = 0;
            for node in nodes {
                count += 1;
                count += count_nodes(&node.children);
            }
            count
        }

        count_nodes(&tree_nodes)
    }

    fn move_selection_up(&mut self) {
        let total_hosts = if self.tree_view_mode {
            self.get_tree_item_count()
        } else {
            self.ptp_tracker.get_hosts().len()
        };

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
        let total_hosts = if self.tree_view_mode {
            self.get_tree_item_count()
        } else {
            self.ptp_tracker.get_hosts().len()
        };

        if total_hosts > 0 && self.selected_index < total_hosts - 1 {
            self.selected_index += 1;
            self.update_selected_host(self.selected_index);
            // Scroll down immediately if we're at the bottom of the visible area
            let last_visible_index =
                self.host_scroll_offset + self.visible_height.saturating_sub(1);
            if self.selected_index > last_visible_index {
                let max_scroll_offset = total_hosts.saturating_sub(self.visible_height);
                self.host_scroll_offset = max_scroll_offset;
            }
        }
    }

    pub fn ensure_host_visible(&mut self, visible_height: usize) {
        let total_hosts = if self.tree_view_mode {
            self.get_tree_item_count()
        } else {
            self.ptp_tracker.get_hosts().len()
        };

        if total_hosts == 0 || visible_height == 0 {
            return;
        }

        // Ensure selection is within bounds
        if self.selected_index >= total_hosts {
            self.selected_index = total_hosts.saturating_sub(1);
            self.host_selection_changed = true;
        }

        // Calculate the maximum scroll offset that still shows content
        // For N hosts and V visible rows, max scroll is N-V (but never negative)
        let max_scroll_offset = total_hosts.saturating_sub(visible_height);

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
        if self.ptp_tracker.get_hosts().is_empty() {
            return;
        }

        // Move up by 10 items or to the beginning
        let old_index = self.selected_index;
        self.selected_index = self.selected_index.saturating_sub(10);

        if self.selected_index != old_index {
            self.update_selected_host(self.selected_index);
            self.host_selection_changed = true;
        }
    }

    pub fn move_selection_page_down(&mut self, visible_height: usize) {
        let total_hosts = if self.tree_view_mode {
            self.get_tree_item_count()
        } else {
            self.ptp_tracker.get_hosts().len()
        };

        if total_hosts == 0 || visible_height == 0 {
            return;
        }

        // Move down by 10 items or to the end
        let old_index = self.selected_index;
        self.selected_index = (self.selected_index + 10).min(total_hosts - 1);

        if self.selected_index != old_index {
            self.update_selected_host(self.selected_index);
        }

        let max_scroll_offset = total_hosts.saturating_sub(visible_height);

        // Adjust scroll position if necessary
        let last_visible_index = self.host_scroll_offset + visible_height.saturating_sub(1);
        if self.selected_index > last_visible_index {
            self.host_scroll_offset = (self.selected_index + 1)
                .saturating_sub(visible_height)
                .min(max_scroll_offset);
        }
    }

    pub fn move_selection_to_top(&mut self) {
        self.selected_index = 0;
        self.host_scroll_offset = 0;
        self.update_selected_host(0);
    }

    pub fn move_selection_to_bottom(&mut self, visible_height: usize) {
        let total_hosts = if self.tree_view_mode {
            self.get_tree_item_count()
        } else {
            self.ptp_tracker.get_hosts().len()
        };

        if total_hosts > 0 {
            self.selected_index = total_hosts - 1;
            self.update_selected_host(self.selected_index);

            // Set scroll to show the bottom of the list
            let max_scroll_offset = total_hosts.saturating_sub(visible_height);
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
                SortColumn::Vendor => {
                    let a_vendor = a.get_vendor_name().unwrap_or("");
                    let b_vendor = b.get_vendor_name().unwrap_or("");
                    a_vendor.cmp(b_vendor)
                }
            };

            if self.sort_ascending {
                comparison
            } else {
                comparison.reverse()
            }
        });

        hosts
    }

    pub fn get_hosts_tree(&self) -> Vec<TreeNode> {
        let hosts = self.ptp_tracker.get_hosts();
        let mut tree_nodes = Vec::new();
        let mut processed = std::collections::HashSet::new();

        // Build a map of transmitter -> receivers for quick lookup using indices
        let mut transmitter_to_receiver_indices: std::collections::HashMap<
            ClockIdentity,
            Vec<usize>,
        > = std::collections::HashMap::new();

        for (i, host) in hosts.iter().enumerate() {
            if let PtpHostState::TimeReceiver(receiver_state) = &host.state
                && let Some(transmitter_id) = receiver_state.selected_transmitter_identity
            {
                transmitter_to_receiver_indices
                    .entry(transmitter_id)
                    .or_default()
                    .push(i);
            }
        }

        // Find root transmitters using indices to avoid cloning
        let mut root_transmitter_indices: Vec<_> = hosts
            .iter()
            .enumerate()
            .filter(|(_, host)| matches!(host.state, PtpHostState::TimeTransmitter(_)))
            .map(|(i, _)| i)
            .collect();

        // Sort root transmitters by the current sort column
        root_transmitter_indices.sort_by(|&a, &b| {
            let host_a = hosts[a];
            let host_b = hosts[b];
            self.compare_hosts_by_sort_column(host_a, host_b)
        });

        // Build tree recursively
        for &transmitter_idx in &root_transmitter_indices {
            let transmitter = hosts[transmitter_idx];
            if !processed.contains(&transmitter.clock_identity) {
                let node = self.build_tree_node(
                    &hosts,
                    transmitter_idx,
                    &transmitter_to_receiver_indices,
                    &mut processed,
                    0,
                );
                tree_nodes.push(node);
            }
        }

        // Add any remaining hosts that weren't part of the tree (orphaned hosts)
        let mut orphaned_indices: Vec<_> = hosts
            .iter()
            .enumerate()
            .filter(|(_, host)| !processed.contains(&host.clock_identity))
            .map(|(i, _)| i)
            .collect();

        // Sort orphaned hosts by current sort column
        orphaned_indices.sort_by(|&a, &b| {
            let host_a = hosts[a];
            let host_b = hosts[b];
            self.compare_hosts_by_sort_column(host_a, host_b)
        });

        for &host_idx in &orphaned_indices {
            let host = hosts[host_idx];
            tree_nodes.push(TreeNode {
                host: (*host).clone(),
                children: Vec::new(),
                depth: 0,
                is_primary_transmitter: matches!(host.state, PtpHostState::TimeTransmitter(_)),
            });
        }

        tree_nodes
    }

    /// Compare two hosts by the current sort column and direction
    fn compare_hosts_by_sort_column(&self, a: &PtpHost, b: &PtpHost) -> std::cmp::Ordering {
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
                    PtpHostState::TimeTransmitter(s) => s.clock_class.map_or(255, |c| c.class()),
                    _ => 255,
                };
                let b_clock_class = match &b.state {
                    PtpHostState::TimeTransmitter(s) => s.clock_class.map_or(255, |c| c.class()),
                    _ => 255,
                };
                a_clock_class.cmp(&b_clock_class)
            }
            SortColumn::SelectedTransmitter => {
                let a_sel = match &a.state {
                    PtpHostState::TimeReceiver(s) => {
                        s.selected_transmitter_identity.unwrap_or_default()
                    }
                    _ => ClockIdentity::default(),
                };

                let b_sel = match &b.state {
                    PtpHostState::TimeReceiver(s) => {
                        s.selected_transmitter_identity.unwrap_or_default()
                    }
                    _ => ClockIdentity::default(),
                };

                a_sel.cmp(&b_sel)
            }
            SortColumn::MessageCount => a
                .total_messages_sent_count
                .cmp(&b.total_messages_sent_count),
            SortColumn::LastSeen => a.last_seen.cmp(&b.last_seen),
            SortColumn::Vendor => {
                let a_vendor = a.get_vendor_name().unwrap_or("");
                let b_vendor = b.get_vendor_name().unwrap_or("");
                a_vendor.cmp(b_vendor)
            }
        };

        if self.sort_ascending {
            comparison
        } else {
            comparison.reverse()
        }
    }

    fn build_tree_node(
        &self,
        hosts: &[&PtpHost],
        host_idx: usize,
        transmitter_to_receiver_indices: &std::collections::HashMap<ClockIdentity, Vec<usize>>,
        processed: &mut std::collections::HashSet<ClockIdentity>,
        depth: usize,
    ) -> TreeNode {
        let host = hosts[host_idx];
        processed.insert(host.clock_identity);

        let is_primary_transmitter = match &host.state {
            PtpHostState::TimeTransmitter(transmitter_state) => {
                // Use existing BMCA winner detection
                transmitter_state.is_bmca_winner
            }
            _ => false,
        };

        let mut children = Vec::new();

        // Find receivers for this transmitter and sort them
        if let Some(receiver_indices) = transmitter_to_receiver_indices.get(&host.clock_identity) {
            let mut sorted_receiver_indices = receiver_indices.clone();
            sorted_receiver_indices
                .sort_by(|&a, &b| self.compare_hosts_by_sort_column(hosts[a], hosts[b]));

            for &receiver_idx in &sorted_receiver_indices {
                let receiver = hosts[receiver_idx];
                if !processed.contains(&receiver.clock_identity) {
                    let child_node = self.build_tree_node(
                        hosts,
                        receiver_idx,
                        transmitter_to_receiver_indices,
                        processed,
                        depth + 1,
                    );
                    children.push(child_node);
                }
            }
        }

        TreeNode {
            host: (*host).clone(),
            children,
            depth,
            is_primary_transmitter,
        }
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

    pub fn get_packet_history(&self) -> Vec<ParsedPacket> {
        // Return packets from the currently selected host
        if let Some(ref selected_host_id) = self.selected_host_id
            && let Some(history) = self.ptp_tracker.get_host_packet_history(*selected_host_id)
        {
            return history;
        }

        Vec::new()
    }

    fn find_host_index(&self, clock_identity: ClockIdentity) -> Option<usize> {
        if self.tree_view_mode {
            // In tree mode, search through tree structure
            let tree_nodes = self.get_hosts_tree();
            let mut current_index = 0;

            fn find_in_tree(
                nodes: &[TreeNode],
                target_id: ClockIdentity,
                current_index: &mut usize,
            ) -> Option<usize> {
                for node in nodes {
                    if node.host.clock_identity == target_id {
                        return Some(*current_index);
                    }
                    *current_index += 1;

                    if let Some(result) = find_in_tree(&node.children, target_id, current_index) {
                        return Some(result);
                    }
                }
                None
            }

            find_in_tree(&tree_nodes, clock_identity, &mut current_index)
        } else {
            // In flat mode, search through flat host list
            self.get_hosts()
                .iter()
                .position(|host| host.clock_identity == clock_identity)
        }
    }

    fn get_host_count(&self) -> usize {
        if self.tree_view_mode {
            self.get_tree_item_count()
        } else {
            self.ptp_tracker.get_hosts().len()
        }
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
        if let Some(ref stored_host_id) = self.selected_host_id
            && let Some(found_index) = self.find_host_index(*stored_host_id)
        {
            // Found the stored host, select it
            self.selected_index = found_index;
            self.update_selected_host(found_index);
            return;
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
        self.auto_scroll_packets = !self.auto_scroll_packets;
    }

    pub fn is_packet_history_expanded(&self) -> bool {
        self.packet_history_expanded
    }

    fn move_packet_selection_up(&mut self) {
        if self.selected_packet_index > 0 {
            self.selected_packet_index -= 1;
            self.auto_scroll_packets = false;
            self.packet_selection_changed = true;
        }
    }

    fn move_packet_selection_down(&mut self) {
        let packet_count = self.get_packet_history().len();
        if packet_count > 0 && self.selected_packet_index < packet_count - 1 {
            self.selected_packet_index += 1;
            self.auto_scroll_packets = false;
            self.packet_selection_changed = true;
        }
    }

    fn move_packet_selection_page_up(&mut self) {
        let visible_height = self.visible_packet_height;
        let old_index = self.selected_packet_index;
        self.selected_packet_index = self.selected_packet_index.saturating_sub(visible_height);
        self.auto_scroll_packets = false;
        if self.selected_packet_index != old_index {
            self.packet_selection_changed = true;
        }
    }

    fn move_packet_selection_page_down(&mut self) {
        let packet_count = self.get_packet_history().len();
        let visible_height = self.visible_packet_height;
        if packet_count > 0 {
            let old_index = self.selected_packet_index;
            self.selected_packet_index =
                (self.selected_packet_index + visible_height).min(packet_count - 1);
            self.auto_scroll_packets = false;
            if self.selected_packet_index != old_index {
                self.packet_selection_changed = true;
            }
        }
    }

    fn move_packet_selection_to_top(&mut self) {
        let old_index = self.selected_packet_index;
        self.selected_packet_index = 0;
        self.auto_scroll_packets = false;
        if self.selected_packet_index != old_index {
            self.packet_selection_changed = true;
        }
    }

    fn move_packet_selection_to_bottom(&mut self) {
        let packet_count = self.get_packet_history().len();
        if packet_count > 0 {
            let old_index = self.selected_packet_index;
            self.selected_packet_index = packet_count - 1;
            self.auto_scroll_packets = false;
            if self.selected_packet_index != old_index {
                self.packet_selection_changed = true;
            }
        }
    }

    pub fn ensure_packet_visible(&mut self) {
        let visible_height = if self.visible_packet_height == 0 {
            // Defensive fallback if height hasn't been set yet
            if self.packet_history_expanded { 20 } else { 8 }
        } else {
            self.visible_packet_height
        };
        let packet_count = self.get_packet_history().len();

        if packet_count == 0 {
            return;
        }

        // Ensure selected packet is within bounds
        self.selected_packet_index = self
            .selected_packet_index
            .min(packet_count.saturating_sub(1));

        // Adjust scroll offset to make selected packet visible
        if self.selected_packet_index < self.packet_scroll_offset {
            self.packet_scroll_offset = self.selected_packet_index;
        } else if self.selected_packet_index >= self.packet_scroll_offset + visible_height {
            self.packet_scroll_offset = self
                .selected_packet_index
                .saturating_sub(visible_height - 1);
        }

        // Ensure scroll offset doesn't go beyond available packets
        let max_scroll = packet_count.saturating_sub(visible_height);
        self.packet_scroll_offset = self.packet_scroll_offset.min(max_scroll);
    }

    pub fn set_visible_packet_height(&mut self, height: usize) {
        self.visible_packet_height = height;
    }

    pub fn get_selected_packet(&self) -> Option<ParsedPacket> {
        let packets = self.get_packet_history();
        if self.selected_packet_index < packets.len() {
            Some(packets[self.selected_packet_index].clone())
        } else {
            None
        }
    }

    pub fn get_modal_packet(&self) -> Option<&ParsedPacket> {
        self.modal_packet.as_ref()
    }

    pub fn get_reference_timestamp(&self) -> Option<std::time::SystemTime> {
        self.ptp_tracker.raw_socket_receiver.get_last_timestamp()
    }

    fn scroll_modal_up(&mut self) {
        if self.modal_scroll_offset > 0 {
            self.modal_scroll_offset -= 1;
        }
    }

    fn scroll_modal_down(&mut self) {
        self.modal_scroll_offset += 1;
        // Bounds will be enforced in the UI rendering
    }

    pub fn scroll_modal_page_up(&mut self, page_size: usize) {
        self.modal_scroll_offset = self.modal_scroll_offset.saturating_sub(page_size);
    }

    pub fn scroll_modal_page_down(&mut self, page_size: usize) {
        self.modal_scroll_offset += page_size;
        // Bounds will be enforced in the UI rendering
    }

    fn scroll_modal_to_top(&mut self) {
        self.modal_scroll_offset = 0;
    }

    fn scroll_modal_to_bottom(&mut self) {
        // This will be properly set when clamp_modal_scroll is called with actual dimensions
        self.modal_scroll_offset = usize::MAX; // Will be clamped to show last line
    }

    pub fn clamp_modal_scroll(&mut self, total_lines: usize, visible_height: usize) {
        self.modal_visible_height = visible_height;
        // Ensure we can always see the last line when scrolled to bottom
        let max_scroll = total_lines.saturating_sub(visible_height);
        self.modal_scroll_offset = self.modal_scroll_offset.min(max_scroll);
    }

    // Host details scroll methods
    fn scroll_host_details_up(&mut self) {
        if self.host_details_scroll_offset > 0 {
            self.host_details_scroll_offset -= 1;
        }
    }

    fn scroll_host_details_down(&mut self) {
        self.host_details_scroll_offset += 1;
        // Bounds will be enforced in the UI rendering
    }

    fn scroll_host_details_page_up(&mut self) {
        self.host_details_scroll_offset = self
            .host_details_scroll_offset
            .saturating_sub(self.host_details_visible_height);
    }

    fn scroll_host_details_page_down(&mut self) {
        self.host_details_scroll_offset += self.host_details_visible_height;
        // Bounds will be enforced in the UI rendering
    }

    fn scroll_host_details_to_top(&mut self) {
        self.host_details_scroll_offset = 0;
    }

    fn scroll_host_details_to_bottom(&mut self) {
        // This will be properly set when clamp_host_details_scroll is called with actual dimensions
        self.host_details_scroll_offset = usize::MAX; // Will be clamped to show last line
    }
}
