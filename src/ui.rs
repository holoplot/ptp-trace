use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, Wrap},
    Frame,
};

use crate::{
    app::{ActiveView, App, SortColumn, TreeNode},
    ptp::{PtpHost, PtpHostState},
    types::{format_timestamp, PtpClockAccuracy, PtpClockClass},
    version,
};

// Helper function to flatten tree nodes for display
fn flatten_tree_nodes(nodes: &[TreeNode]) -> Vec<(&TreeNode, usize, bool)> {
    let mut flattened = Vec::new();
    let mut stack = Vec::new();
    let mut index = 0;

    // Push initial nodes onto stack with their sibling information
    for (i, node) in nodes.iter().enumerate().rev() {
        let is_last_child = i == nodes.len() - 1;
        stack.push((node, is_last_child));
    }

    // Process nodes iteratively
    while let Some((node, is_last_child)) = stack.pop() {
        flattened.push((node, index, is_last_child));
        index += 1;

        // Push children in reverse order so they're processed in correct order
        for (i, child) in node.children.iter().enumerate().rev() {
            let child_is_last = i == node.children.len() - 1;
            stack.push((child, child_is_last));
        }
    }

    flattened
}

// Helper function to create a table row for a host
fn create_host_row<'a>(
    host: &PtpHost,
    clock_identity_display: String,
    actual_i: usize,
    selected_index: usize,
    theme: &crate::themes::Theme,
    local_ips: &[std::net::IpAddr],
    is_primary_transmitter: Option<bool>,
) -> Row<'a> {
    let state_color = theme.get_state_color(&host.state);

    let time_since_last_seen = host.time_since_last_seen();
    let last_seen_str = if time_since_last_seen.as_secs() < 60 {
        format!("{}s", time_since_last_seen.as_secs())
    } else {
        format!("{}m", time_since_last_seen.as_secs() / 60)
    };

    let style = if actual_i == selected_index {
        Style::default()
            .bg(theme.selected_row_background)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };

    let mut state_display = format!("{}", host.state.short_string());
    if host.has_local_ip(local_ips) {
        state_display = format!("{}*", state_display);
    }

    // Add PTT indicator for primary transmitters (BMCA winners) in tree mode
    if is_primary_transmitter.unwrap_or(false) {
        state_display = format!("PTT");
    }

    let ip_display = if let Some(primary_ip) = host.get_primary_ip() {
        if host.has_multiple_ips() {
            format!("{} (+{})", primary_ip, host.get_ip_count() - 1)
        } else {
            format!("{}", primary_ip)
        }
    } else {
        "N/A".to_string()
    };

    let priority1_display = match &host.state {
        PtpHostState::TimeTransmitter(s) => s.priority1.map_or("-".to_string(), |p| p.to_string()),
        _ => "-".to_string(),
    };

    let clock_class_display = match &host.state {
        PtpHostState::TimeTransmitter(s) => {
            s.clock_class.map_or("-".to_string(), |c| c.to_string())
        }
        _ => "-".to_string(),
    };

    let selected_transmitter_cell = match &host.state {
        PtpHostState::TimeReceiver(s) => {
            s.selected_transmitter_identity
                .as_ref()
                .map(|id| {
                    // Add confidence indicator based on relationship quality
                    let (confidence_symbol, confidence_color) =
                        match s.selected_transmitter_confidence {
                            conf if conf >= 0.9 => (
                                " ✓",
                                theme.get_confidence_color(s.selected_transmitter_confidence),
                            ), // High confidence
                            conf if conf >= 0.7 => (
                                " ~",
                                theme.get_confidence_color(s.selected_transmitter_confidence),
                            ), // Good confidence
                            conf if conf >= 0.4 => (
                                " ?",
                                theme.get_confidence_color(s.selected_transmitter_confidence),
                            ), // Medium confidence
                            _ => ("", theme.text_primary), // Low/no confidence
                        };

                    let cell = Cell::from(Line::from(vec![
                        Span::styled(id.to_string(), Style::default().fg(theme.text_primary)),
                        Span::styled(confidence_symbol, Style::default().fg(confidence_color)),
                    ]));
                    cell
                })
                .unwrap_or_else(|| Cell::from("-"))
        }
        _ => Cell::from("-"),
    };

    Row::new(vec![
        Cell::from(state_display).style(Style::default().fg(state_color)),
        Cell::from(clock_identity_display),
        Cell::from(ip_display),
        Cell::from(
            host.domain_number
                .map_or("-".to_string(), |domain| domain.to_string()),
        ),
        Cell::from(priority1_display),
        Cell::from(clock_class_display),
        selected_transmitter_cell,
        Cell::from(host.total_messages_sent_count.to_string()),
        Cell::from(last_seen_str),
    ])
    .style(style)
}

// Helper function to create aligned label-value pairs
fn create_aligned_field<'a>(
    label: &'a str,
    value: String,
    label_width: usize,
    theme: &'a crate::themes::Theme,
) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("{:width$}", label, width = label_width),
            Style::default().fg(theme.text_secondary),
        ),
        Span::styled(value, Style::default().fg(theme.text_primary)),
    ])
}

fn create_aligned_field_with_vendor<'a>(
    label: &'a str,
    value: String,
    vendor_info: String,
    label_width: usize,
    theme: &'a crate::themes::Theme,
    value_color: Color,
) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("{:width$}", label, width = label_width),
            Style::default().fg(theme.text_secondary),
        ),
        Span::styled(value, Style::default().fg(value_color)),
        Span::styled(vendor_info, Style::default().fg(theme.vendor_text)),
    ])
}

pub fn ui(f: &mut Frame, app: &mut App) {
    let chunks = if app.is_packet_history_expanded() {
        // Expanded view: split roughly 50/50 between hosts and packets
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),      // Header
                Constraint::Percentage(50), // Main content (hosts + details)
                Constraint::Percentage(50), // Expanded packet history
            ])
            .split(f.size())
    } else {
        // Normal view: smaller packet history area
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Min(15),    // Main content (hosts + details)
                Constraint::Length(10), // Compact packet history (fixed height)
            ])
            .split(f.size())
    };

    // Render header
    render_header(f, chunks[0], app);

    // Render main content
    if app.show_help {
        render_help(f, chunks[1], app);
    } else {
        render_main_content(f, chunks[1], app);
        render_packet_history(f, chunks[2], app);
    }
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let theme = &app.theme;

    // Create header content with version and build info
    let mut header_spans = vec![
        Span::styled(
            "PTP Network Tracer",
            Style::default()
                .fg(theme.header_fg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}", version::get_version()),
            Style::default()
                .fg(theme.text_accent)
                .add_modifier(Modifier::BOLD),
        ),
    ];

    // Add PAUSED indicator if paused
    if app.paused {
        header_spans.push(Span::styled(
            " [PAUSED]",
            Style::default()
                .fg(theme.text_accent)
                .add_modifier(Modifier::BOLD | Modifier::SLOW_BLINK),
        ));
    }

    let header_content = vec![
        Line::from(header_spans),
        Line::from(vec![Span::styled(
            format!(
                "Built: {} | Git: {}",
                version::get_build_time(),
                version::get_git_hash()
            ),
            Style::default()
                .fg(theme.text_secondary)
                .add_modifier(Modifier::ITALIC),
        )]),
    ];

    let header = Paragraph::new(header_content)
        .style(Style::default().bg(theme.header_bg))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme.border_normal)),
        );

    f.render_widget(header, area);
}

/// Resolve clock class to human-readable description
pub fn format_clock_class(cc: Option<PtpClockClass>) -> String {
    match cc {
        None => "N/A".to_string(),
        Some(class) => class.to_string(),
    }
}

/// Resolve clock accuracy
pub fn format_clock_accuracy(ca: Option<PtpClockAccuracy>) -> String {
    match ca {
        None => "N/A".to_string(),
        Some(accuracy) => accuracy.to_string(),
    }
}

fn render_main_content(f: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    // Left panel: PTP hosts list
    render_hosts_table(f, chunks[0], app);

    // Right panel: Statistics and details
    render_stats_panel(f, chunks[1], app);
}

fn render_hosts_table(f: &mut Frame, area: Rect, app: &mut App) {
    // Calculate visible rows (subtract 4 for top border, header row, header bottom margin, and bottom border)
    let visible_height = area.height.saturating_sub(4) as usize;

    // Store visible height in app for key handling
    app.set_visible_height(visible_height);

    // Ensure the selected item is visible
    app.ensure_host_visible(visible_height);

    let theme = &app.theme;
    let _is_focused = true; // Hosts are always focused now
    let selected_index = app.get_selected_index();
    let updated_scroll_offset = app.get_host_scroll_offset();

    // Get local IPs for comparison
    let local_ips = app.ptp_tracker.get_local_ips();

    let sort_column = app.get_sort_column();
    let headers = [
        (SortColumn::State, "State"),
        (SortColumn::ClockIdentity, "Clock Identity"),
        (SortColumn::IpAddress, "IP Address"),
        (SortColumn::Domain, "Dom"),
        (SortColumn::Priority, "Pri"),
        (SortColumn::ClockClass, "CC"),
        (SortColumn::SelectedTransmitter, "Selected Transmitter"),
        (SortColumn::MessageCount, "Msgs"),
        (SortColumn::LastSeen, "Last Seen"),
    ];

    let header_cells = headers.iter().map(|(col_type, display_name)| {
        let style = if col_type == sort_column {
            Style::default()
                .fg(theme.sort_column_active)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(theme.table_header)
                .add_modifier(Modifier::BOLD)
        };
        Cell::from(*display_name).style(style)
    });

    let header = Row::new(header_cells).height(1);

    // Get hosts data based on tree view mode
    let (total_count, rows) = if app.tree_view_mode {
        // Tree view mode
        let tree_nodes = app.get_hosts_tree();
        let flattened_nodes = flatten_tree_nodes(&tree_nodes);
        let total_count = flattened_nodes.len();

        // Apply scrolling - only show visible rows
        let visible_nodes: Vec<_> = flattened_nodes
            .iter()
            .skip(updated_scroll_offset)
            .take(visible_height)
            .collect();

        let rows: Vec<Row> = visible_nodes
            .iter()
            .enumerate()
            .map(|(visible_i, (node, _flat_index, is_last_child))| {
                let actual_i = visible_i + updated_scroll_offset;
                let host = &node.host;

                // Create indentation for tree structure
                let indent = "  ".repeat(node.depth);
                let tree_prefix = if node.depth > 0 {
                    if *is_last_child {
                        "└─ "
                    } else {
                        "├─ "
                    }
                } else {
                    ""
                };

                let clock_identity_display =
                    format!("{}{}{}", indent, tree_prefix, host.clock_identity);

                create_host_row(
                    host,
                    clock_identity_display,
                    actual_i,
                    selected_index,
                    theme,
                    &local_ips,
                    Some(node.is_primary_transmitter),
                )
            })
            .collect();

        (total_count, rows)
    } else {
        // Table view mode (original)
        let hosts = app.get_hosts();
        let total_count = hosts.len();

        // Apply scrolling - only show visible rows
        let visible_hosts: Vec<_> = hosts
            .iter()
            .skip(updated_scroll_offset)
            .take(visible_height)
            .collect();

        let rows: Vec<Row> = visible_hosts
            .iter()
            .enumerate()
            .map(|(visible_i, host)| {
                let actual_i = visible_i + updated_scroll_offset;
                let clock_identity_display = host.clock_identity.to_string();

                create_host_row(
                    host,
                    clock_identity_display,
                    actual_i,
                    selected_index,
                    theme,
                    &local_ips,
                    None,
                )
            })
            .collect();

        (total_count, rows)
    };

    let widths = [
        Constraint::Length(5),  // State
        Constraint::Min(23),    // Clock Identity
        Constraint::Length(24), // IP Address
        Constraint::Length(3),  // Domain
        Constraint::Length(3),  // Priority
        Constraint::Length(3),  // Clock Class
        Constraint::Length(25), // Selected Transmitter
        Constraint::Length(5),  // Message Count
        Constraint::Length(10), // Last Seen
    ];

    let sort_direction = if app.is_sort_ascending() {
        "↑"
    } else {
        "↓"
    };

    let view_indicator = match app.active_view {
        ActiveView::HostTable => " [ACTIVE - TAB to switch]",
        ActiveView::PacketHistory => " [TAB to switch]",
    };

    let title = if app.tree_view_mode {
        format!(
            "PTP Hosts - Tree View - Sort: {}{} (s to cycle, S to reverse){}",
            sort_column.display_name(),
            sort_direction,
            view_indicator
        )
    } else {
        format!(
            "PTP Hosts - Sort: {}{} (s to cycle, S to reverse){}",
            sort_column.display_name(),
            sort_direction,
            view_indicator
        )
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.as_str())
                .border_type(BorderType::Rounded)
                .border_style(match app.active_view {
                    ActiveView::HostTable => Style::default().fg(theme.border_focused),
                    ActiveView::PacketHistory => Style::default().fg(theme.border_normal),
                }),
        )
        .style(Style::default().bg(theme.background))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(">> ");

    f.render_widget(table, area);

    // Render scrollbar if needed
    if total_count > visible_height {
        render_scrollbar(
            f,
            area,
            total_count,
            updated_scroll_offset,
            visible_height,
            theme,
        );
    }
}

fn render_stats_panel(f: &mut Frame, area: Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8), // Summary stats
            Constraint::Min(5),    // Details panel (host or packet)
        ])
        .split(area);

    // Summary statistics
    render_summary_stats(f, chunks[0], app);

    // Show host details (merged with network info)
    render_host_details(f, chunks[1], app);
}

fn render_summary_stats(f: &mut Frame, area: Rect, app: &mut App) {
    let theme = &app.theme;
    let hosts = app.get_hosts();
    let total_hosts = hosts.len();
    let transmitter_count = app.ptp_tracker.get_transmitter_count();
    let receiver_count = app.ptp_tracker.get_receiver_count();

    // Define the width for label alignment in statistics
    const STATS_LABEL_WIDTH: usize = 15; // Width for "Total Hosts: "

    let stats_text = vec![
        create_aligned_field(
            "Total Hosts: ",
            total_hosts.to_string(),
            STATS_LABEL_WIDTH,
            theme,
        ),
        create_aligned_field_with_vendor(
            "Transmitters: ",
            transmitter_count.to_string(),
            String::new(),
            STATS_LABEL_WIDTH,
            theme,
            theme.state_transmitter,
        ),
        create_aligned_field_with_vendor(
            "Receivers: ",
            receiver_count.to_string(),
            String::new(),
            STATS_LABEL_WIDTH,
            theme,
            theme.state_receiver,
        ),
        create_aligned_field(
            "Last packet: ",
            format!("{}s ago", app.ptp_tracker.get_last_packet_age().as_secs()),
            STATS_LABEL_WIDTH,
            theme,
        ),
    ];

    let paragraph = Paragraph::new(stats_text)
        .style(Style::default().fg(theme.text_primary).bg(theme.background))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Statistics")
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme.border_normal)),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn render_host_details(f: &mut Frame, area: Rect, app: &mut App) {
    let theme = &app.theme;

    let details_text = if let Some(ref selected_host_id) = app.selected_host_id {
        if let Some(host) = app.ptp_tracker.get_host_by_clock_identity(selected_host_id) {
            // Get local IPs for comparison
            let local_ips = app.ptp_tracker.get_local_ips();
            // Define the width for label alignment
            const LABEL_WIDTH: usize = 22; // Width for "Follow-Up Timestamp: "

            let mut details_text = vec![
                // Host details section
                create_aligned_field_with_vendor(
                    "Clock Identity: ",
                    host.clock_identity.to_string(),
                    host.get_vendor_name()
                        .map(|vendor| format!(" ({})", vendor))
                        .unwrap_or_default(),
                    LABEL_WIDTH,
                    theme,
                    theme.text_primary,
                ),
            ];

            // Add IP addresses with interface info - each on its own row with "IP Address:" label
            for (ip, interfaces) in host.ip_addresses.iter() {
                let s = interfaces.join(", ");

                let ip_display = if local_ips.contains(ip) {
                    format!("{} ({}) *", ip, s)
                } else {
                    format!("{} ({})", ip, s)
                };
                details_text.push(create_aligned_field(
                    "IP Address: ",
                    ip_display,
                    LABEL_WIDTH,
                    theme,
                ));
            }

            details_text.extend(vec![
                create_aligned_field_with_vendor(
                    "State: ",
                    host.state.to_string(),
                    String::new(),
                    LABEL_WIDTH,
                    theme,
                    theme.get_state_color(&host.state),
                ),
                create_aligned_field(
                    "PTP Version: ",
                    host.last_version
                        .map_or("N/A".to_string(), |v| v.to_string()),
                    LABEL_WIDTH,
                    theme,
                ),
                create_aligned_field(
                    "Domain: ",
                    host.domain_number
                        .map(|d| d.to_string())
                        .unwrap_or("N/A".to_string()),
                    LABEL_WIDTH,
                    theme,
                ),
                create_aligned_field(
                    "Last Correction: ",
                    host.last_correction_field
                        .map_or("N/A".to_string(), |v| v.to_string()),
                    LABEL_WIDTH,
                    theme,
                ),
                create_aligned_field(
                    "Last Seen: ",
                    format!("{:.1}s ago", host.time_since_last_seen().as_secs_f64()),
                    LABEL_WIDTH,
                    theme,
                ),
            ]);

            match &host.state {
                PtpHostState::Listening => {}
                PtpHostState::TimeTransmitter(s) => {
                    details_text.extend(vec![
                        Line::from(""),
                        Line::from(vec![Span::styled(
                            "Time Transmitter:",
                            Style::default()
                                .fg(theme.text_accent)
                                .add_modifier(Modifier::BOLD),
                        )]),
                        create_aligned_field(
                            "Priority 1: ",
                            s.priority1.map_or("N/A".to_string(), |p| p.to_string()),
                            LABEL_WIDTH,
                            theme,
                        ),
                        create_aligned_field(
                            "Priority 2: ",
                            s.priority2.map_or("N/A".to_string(), |p| p.to_string()),
                            LABEL_WIDTH,
                            theme,
                        ),
                        create_aligned_field(
                            "Clock Class: ",
                            format_clock_class(s.clock_class),
                            LABEL_WIDTH,
                            theme,
                        ),
                        create_aligned_field(
                            "Accuracy: ",
                            format_clock_accuracy(s.clock_accuracy),
                            LABEL_WIDTH,
                            theme,
                        ),
                        create_aligned_field(
                            "Log Variance: ",
                            s.offset_scaled_log_variance
                                .map_or("N/A".to_string(), |v| v.to_string()),
                            LABEL_WIDTH,
                            theme,
                        ),
                        create_aligned_field(
                            "Primary Identity: ",
                            s.ptt_identifier
                                .map_or("N/A".to_string(), |p| p.to_string()),
                            LABEL_WIDTH,
                            theme,
                        ),
                        create_aligned_field(
                            "UTC Offset: ",
                            s.current_utc_offset
                                .map_or("N/A".to_string(), |o| o.to_string()),
                            LABEL_WIDTH,
                            theme,
                        ),
                        create_aligned_field(
                            "Announce TS: ",
                            format_timestamp(s.last_announce_origin_timestamp),
                            LABEL_WIDTH,
                            theme,
                        ),
                        create_aligned_field(
                            "Sync TS: ",
                            format_timestamp(s.last_sync_origin_timestamp),
                            LABEL_WIDTH,
                            theme,
                        ),
                        create_aligned_field(
                            "Follow-Up TS: ",
                            format_timestamp(s.last_followup_origin_timestamp),
                            LABEL_WIDTH,
                            theme,
                        ),
                    ]);
                }
                PtpHostState::TimeReceiver(s) => {
                    details_text.extend(vec![
                        Line::from(""),
                        Line::from(vec![Span::styled(
                            "Time Receiver:",
                            Style::default()
                                .fg(theme.text_accent)
                                .add_modifier(Modifier::BOLD),
                        )]),
                        create_aligned_field_with_vendor(
                            "Selected Transmitter: ",
                            match s.selected_transmitter_identity {
                                Some(identity) => identity.to_string(),
                                None => "None".to_string(),
                            },
                            s.selected_transmitter_identity
                                .and_then(|id| id.extract_vendor_name())
                                .map(|vendor| format!(" ({})", vendor))
                                .unwrap_or_default(),
                            LABEL_WIDTH,
                            theme,
                            theme.get_confidence_color(s.selected_transmitter_confidence),
                        ),
                        create_aligned_field(
                            "Last E2E Delay TS: ",
                            format_timestamp(s.last_delay_response_origin_timestamp),
                            LABEL_WIDTH,
                            theme,
                        ),
                        create_aligned_field(
                            "Last P2P Delay TS: ",
                            format_timestamp(s.last_pdelay_response_origin_timestamp),
                            LABEL_WIDTH,
                            theme,
                        ),
                        create_aligned_field(
                            "Last P2P Delay FU TS: ",
                            format_timestamp(s.last_pdelay_follow_up_timestamp),
                            LABEL_WIDTH,
                            theme,
                        ),
                    ]);
                }
            }

            details_text.extend(vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Message Counts:",
                    Style::default()
                        .fg(theme.text_accent)
                        .add_modifier(Modifier::BOLD),
                )]),
                create_aligned_field(
                    "  Announce: ",
                    host.announce_count.to_string(),
                    LABEL_WIDTH,
                    theme,
                ),
                create_aligned_field("  Sync: ", host.sync_count.to_string(), LABEL_WIDTH, theme),
                create_aligned_field(
                    "  Delay Req/Resp: ",
                    format!("{}/{}", host.delay_req_count, host.delay_resp_count),
                    LABEL_WIDTH,
                    theme,
                ),
                create_aligned_field(
                    "  PDelay Req/Resp/FU: ",
                    format!(
                        "{}/{}/{}",
                        host.pdelay_req_count,
                        host.pdelay_resp_count,
                        host.pdelay_resp_follow_up_count
                    ),
                    LABEL_WIDTH,
                    theme,
                ),
                create_aligned_field(
                    "  Management/Signaling: ",
                    format!(
                        "{}/{}",
                        host.management_message_count, host.signaling_message_count
                    ),
                    LABEL_WIDTH,
                    theme,
                ),
            ]);

            details_text
        } else {
            vec![
                Line::from("No host found with selected ID"),
                Line::from(""),
                Line::from("This may indicate a synchronization issue"),
            ]
        }
    } else {
        vec![
            Line::from("No host selected"),
            Line::from(""),
            Line::from("Use ↑/↓ to select a host"),
            Line::from("Press Tab to switch to packet panel"),
        ]
    };

    let details_paragraph = Paragraph::new(details_text)
        .style(Style::default().fg(theme.text_primary).bg(theme.background))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Host Details")
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme.border_normal)),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(details_paragraph, area);
}

fn render_help(f: &mut Frame, area: Rect, app: &App) {
    let theme = &app.theme;

    let time_transmitter_state =
        PtpHostState::TimeTransmitter(crate::ptp::PtpHostStateTimeTransmitter::default());
    let time_receiver_state =
        PtpHostState::TimeReceiver(crate::ptp::PtpHostStateTimeReceiver::default());
    let listening_state = PtpHostState::Listening;

    let help_text = vec![
        Line::from(vec![Span::styled(
            "PTP Network Tracer Help",
            Style::default()
                .fg(theme.text_accent)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Navigation:",
            Style::default()
                .fg(theme.table_header)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  Tab        - Switch between host table and packet history"),
        Line::from("  ↑/k        - Move selection up (in active view)"),
        Line::from("  ↓/j        - Move selection down (in active view)"),
        Line::from("  PgUp/PgDn  - Page up/down (10 items)"),
        Line::from("  Home/End   - Jump to top/bottom"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Actions:",
            Style::default()
                .fg(theme.table_header)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  r          - Refresh/rescan network"),
        Line::from("  Ctrl+L     - Refresh/redraw screen"),
        Line::from("  c          - Clear all hosts and packet histories"),
        Line::from("  x          - Clear packet history for selected host"),
        Line::from("  p          - Toggle pause mode"),
        Line::from("  s          - Cycle host table sorting"),
        Line::from("  a          - Previous sort column"),
        Line::from("  S          - Reverse sort direction"),
        Line::from("  e          - Toggle expanded packet history"),
        Line::from("  d          - Toggle debug mode"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "General:",
            Style::default()
                .fg(theme.table_header)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  h/F1       - Show/hide this help"),
        Line::from("  q/Esc      - Quit application"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Legend:",
            Style::default()
                .fg(theme.table_header)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled(
                format!("  {}", time_transmitter_state.short_string()),
                Style::default().fg(theme.get_state_color(&time_transmitter_state)),
            ),
            Span::raw(format!("  - {}", time_receiver_state)),
        ]),
        Line::from(vec![
            Span::styled(
                "  PTT",
                Style::default().fg(theme.get_state_color(&time_transmitter_state)),
            ),
            Span::raw(format!(" - {} (Primary)", time_transmitter_state)),
        ]),
        Line::from(vec![
            Span::styled(
                format!("  {}", time_receiver_state.short_string()),
                Style::default().fg(theme.get_state_color(&time_receiver_state)),
            ),
            Span::raw(format!("  - {}", time_receiver_state)),
        ]),
        Line::from(vec![
            Span::styled(
                format!("  {}", listening_state.short_string()),
                Style::default().fg(theme.get_state_color(&listening_state)),
            ),
            Span::raw(format!("  - {}", listening_state)),
        ]),
        Line::from(vec![
            Span::styled("  *", Style::default().fg(theme.text_primary)),
            Span::raw("  - Local machine (your own host)"),
        ]),
    ];

    let help_paragraph = Paragraph::new(help_text)
        .style(Style::default().fg(theme.text_primary).bg(theme.background))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Help")
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme.border_normal)),
        )
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });

    f.render_widget(help_paragraph, area);
}

fn render_scrollbar(
    f: &mut Frame,
    area: Rect,
    total_items: usize,
    scroll_offset: usize,
    visible_items: usize,
    theme: &crate::themes::Theme,
) {
    if total_items <= visible_items {
        return;
    }

    let scrollbar_area = Rect {
        x: area.x + area.width - 1,
        y: area.y + 1, // Skip top border
        width: 1,
        height: area.height.saturating_sub(2), // Skip top and bottom borders
    };

    let scrollbar_height = scrollbar_area.height as usize;
    let thumb_size = (visible_items * scrollbar_height / total_items).max(1);

    // Calculate thumb position properly - when at max scroll, thumb should be at bottom
    let max_scroll_offset = total_items.saturating_sub(visible_items);
    let thumb_position = if max_scroll_offset == 0 {
        0
    } else {
        // Scale scroll position to scrollbar height, ensuring thumb can reach the bottom
        let max_thumb_position = scrollbar_height.saturating_sub(thumb_size);
        (scroll_offset * max_thumb_position) / max_scroll_offset
    };

    // Draw scrollbar track
    for y in 0..scrollbar_height {
        let cell_area = Rect {
            x: scrollbar_area.x,
            y: scrollbar_area.y + y as u16,
            width: 1,
            height: 1,
        };

        let symbol = if y >= thumb_position && y < thumb_position + thumb_size {
            "█" // Thumb
        } else {
            "░" // Track
        };

        let style = if y >= thumb_position && y < thumb_position + thumb_size {
            Style::default().fg(theme.border_focused)
        } else {
            Style::default().fg(theme.border_normal)
        };

        f.render_widget(
            ratatui::widgets::Paragraph::new(symbol).style(style),
            cell_area,
        );
    }
}

fn render_packet_history(f: &mut Frame, area: Rect, app: &mut App) {
    let packets = app.get_packet_history();
    let total_packets = packets.len();

    // Calculate how many packets we can display
    let content_height = area.height.saturating_sub(3) as usize; // Subtract borders + header
    let visible_packets = if app.is_packet_history_expanded() {
        content_height
    } else {
        content_height.min(8) // Limit to 8 rows when not expanded
    };

    // Update app with actual visible height
    app.set_visible_packet_height(visible_packets);

    // Auto-scroll to bottom if in host table view and auto-scroll is enabled
    if matches!(app.active_view, ActiveView::HostTable) && app.auto_scroll_packets {
        if total_packets > 0 {
            app.selected_packet_index = total_packets - 1;
            let max_scroll = total_packets.saturating_sub(visible_packets);
            app.packet_scroll_offset = max_scroll;
        }
    } else if matches!(app.active_view, ActiveView::PacketHistory) {
        // Ensure selected packet is visible when in packet history view
        app.ensure_packet_visible();
    }

    // Get theme reference after mutable operations
    let theme = &app.theme;

    // Create title with view indicator
    let selected_host_info = if let Some(ref host_id) = app.selected_host_id {
        host_id.to_string()
    } else {
        "[No host selected]".to_string()
    };

    let view_indicator = match app.active_view {
        ActiveView::PacketHistory => " [ACTIVE - TAB to switch]",
        ActiveView::HostTable => " [TAB to switch]",
    };

    let expanded_status = if app.is_packet_history_expanded() {
        " [EXPANDED]"
    } else {
        ""
    };

    let title = if total_packets > 0 {
        let display_count = visible_packets.min(total_packets);
        format!(
            "Packet History {} ({}/{}) - 'e' to toggle expand{}{}",
            selected_host_info, display_count, total_packets, expanded_status, view_indicator
        )
    } else {
        format!(
            "Packet History{} (No packets yet) - 'e' to toggle expand{}{}",
            selected_host_info, expanded_status, view_indicator
        )
    };

    let border_style = match app.active_view {
        ActiveView::PacketHistory => Style::default().fg(theme.border_focused),
        ActiveView::HostTable => Style::default().fg(theme.border_normal),
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style)
        .style(Style::default().bg(theme.background));

    if total_packets == 0 {
        let message = if app.selected_host_id.is_none() {
            "Select a host to view its packet history."
        } else {
            "No packets captured yet for this host. Packets will appear here as they arrive."
        };
        let no_packets_text = Paragraph::new(message)
            .style(Style::default().fg(theme.text_primary).bg(theme.background))
            .block(block)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        f.render_widget(no_packets_text, area);
        return;
    }

    // Create table headers
    let headers = Row::new(vec![
        Cell::from("Time Ago"),
        Cell::from("VLAN"),
        Cell::from("Source IP"),
        Cell::from("Port"),
        Cell::from("Interface"),
        Cell::from("Version"),
        Cell::from("Message Type"),
        Cell::from("Length"),
        Cell::from("Domain"),
        Cell::from("Seq"),
        Cell::from("Flags"),
        Cell::from("Correction"),
        Cell::from("Interval"),
        Cell::from("Details"),
    ])
    .style(
        Style::default()
            .fg(theme.table_header)
            .add_modifier(Modifier::BOLD),
    );

    // Get visible packets (oldest first now, newest at bottom)
    let scroll_offset = app
        .packet_scroll_offset
        .min(total_packets.saturating_sub(visible_packets));
    let end = (scroll_offset + visible_packets).min(total_packets);
    let visible_packets_slice = if total_packets > 0 {
        &packets[scroll_offset..end]
    } else {
        &[]
    };

    let selected_in_view = app.selected_packet_index.saturating_sub(scroll_offset);

    // Create table rows from visible packets
    let rows: Vec<Row> = visible_packets_slice
        .iter()
        .enumerate()
        .map(|(i, packet)| {
            let elapsed = packet.timestamp.elapsed();
            let time_str = if elapsed.as_secs() < 1 {
                format!("{}ms", elapsed.as_millis())
            } else if elapsed.as_secs() < 60 {
                format!("{:.1}s", elapsed.as_secs_f32())
            } else if elapsed.as_secs() < 3600 {
                format!("{}m{}s", elapsed.as_secs() / 60, elapsed.as_secs() % 60)
            } else {
                format!(
                    "{}h{}m",
                    elapsed.as_secs() / 3600,
                    (elapsed.as_secs() % 3600) / 60
                )
            };

            let header = packet.ptp_message.header();

            let row_style =
                if matches!(app.active_view, ActiveView::PacketHistory) && i == selected_in_view {
                    Style::default()
                        .bg(theme.selected_row_background)
                        .fg(theme.text_primary)
                } else {
                    Style::default()
                };

            Row::new(vec![
                Cell::from(time_str),
                Cell::from(match packet.vlan_id {
                    Some(id) => id.to_string(),
                    None => "-".to_string(),
                }),
                Cell::from(packet.source_ip.to_string()),
                Cell::from(packet.source_port.to_string()),
                Cell::from(packet.interface.clone()),
                Cell::from(format!("v{}", header.version)),
                Cell::from(Span::styled(
                    header.message_type.to_string(),
                    theme.get_message_type_color(&header.message_type),
                )),
                Cell::from(header.message_length.to_string()),
                Cell::from(header.domain_number.to_string()),
                Cell::from(header.sequence_id.to_string()),
                Cell::from(header.flags.short()),
                Cell::from(header.correction_field.value.to_string()),
                Cell::from(header.log_message_interval.to_string()),
                Cell::from(packet.ptp_message.to_string()),
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Length(10),  // Time Ago
        Constraint::Length(5),   // VLAN
        Constraint::Length(15),  // Source IP
        Constraint::Length(5),   // Port
        Constraint::Length(10),  // Interface
        Constraint::Length(5),   // Version
        Constraint::Length(13),  // Message Type
        Constraint::Length(6),   // Length
        Constraint::Length(7),   // Domain
        Constraint::Length(5),   // Sequence
        Constraint::Length(6),   // Flags
        Constraint::Length(11),  // Correction
        Constraint::Length(11),  // Log Interval
        Constraint::Length(100), // Details
    ];

    let table = Table::new(rows, widths)
        .header(headers)
        .block(block)
        .style(Style::default().bg(theme.background));

    f.render_widget(table, area);

    // Render scrollbar if needed
    if total_packets > visible_packets {
        render_scrollbar(
            f,
            area,
            total_packets,
            scroll_offset,
            visible_packets,
            theme,
        );
    }
}
