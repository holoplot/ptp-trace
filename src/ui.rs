use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, Wrap},
    Frame,
};

use crate::{
    app::{App, SortColumn},
    ptp::get_vendor_by_clock_identity,
    version,
};

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
    let header_content = vec![
        Line::from(vec![
            Span::styled(
                "PTP Network Tracer",
                Style::default()
                    .fg(theme.header_fg)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                version::get_version(),
                Style::default()
                    .fg(theme.text_accent)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
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
    let is_focused = true; // Hosts are always focused now
    let hosts = app.get_hosts();
    let selected_index = app.get_selected_index();
    let updated_scroll_offset = app.get_host_scroll_offset();

    let sort_column = app.get_sort_column();
    let headers = [
        (SortColumn::State, "State"),
        (SortColumn::ClockIdentity, "Clock Identity"),
        (SortColumn::IpAddress, "IP Address"),
        (SortColumn::Domain, "Domain"),
        (SortColumn::SelectedLeader, "Selected Leader"),
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

    let header = Row::new(header_cells).height(1).bottom_margin(1);

    // Apply scrolling - only show visible rows
    let visible_hosts: Vec<_> = hosts
        .iter()
        .skip(updated_scroll_offset)
        .take(visible_height)
        .collect();

    let rows = visible_hosts.iter().enumerate().map(|(visible_i, host)| {
        let actual_i = visible_i + updated_scroll_offset;
        let state_color = theme.get_state_color(&host.state);

        let time_since_last_seen = host.time_since_last_seen();
        let last_seen_str = if time_since_last_seen.as_secs() < 60 {
            format!("{}s", time_since_last_seen.as_secs())
        } else {
            format!("{}m", time_since_last_seen.as_secs() / 60)
        };

        let style = if actual_i == selected_index {
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };

        let (_selected_leader_display, selected_leader_cell) = host
            .selected_leader_id
            .as_ref()
            .map(|id| {
                // Add confidence indicator based on relationship quality
                let (confidence_symbol, confidence_color) = match host.selected_leader_confidence {
                    conf if conf >= 0.9 => (
                        " ✓",
                        theme.get_confidence_color(host.selected_leader_confidence),
                    ), // High confidence
                    conf if conf >= 0.7 => (
                        " ~",
                        theme.get_confidence_color(host.selected_leader_confidence),
                    ), // Good confidence
                    conf if conf >= 0.4 => (
                        " ?",
                        theme.get_confidence_color(host.selected_leader_confidence),
                    ), // Medium confidence
                    _ => ("", theme.text_primary), // Low/no confidence
                };

                let cell = Cell::from(Line::from(vec![
                    Span::styled(id.clone(), Style::default().fg(theme.text_primary)),
                    Span::styled(confidence_symbol, Style::default().fg(confidence_color)),
                ]));
                (format!("{}{}", id, confidence_symbol), cell)
            })
            .unwrap_or_else(|| ("None".to_string(), Cell::from("None")));

        Row::new(vec![
            Cell::from(host.state.to_string()).style(Style::default().fg(state_color)),
            Cell::from(host.clock_identity.clone()),
            Cell::from(host.ip_address.to_string()),
            Cell::from(host.domain_number.to_string()),
            selected_leader_cell,
            Cell::from(last_seen_str),
        ])
        .style(style)
    });

    let widths = [
        Constraint::Length(5),  // State
        Constraint::Min(23),    // Clock Identity
        Constraint::Length(15), // IP Address
        Constraint::Length(6),  // Domain
        Constraint::Length(25), // Selected Leader
        Constraint::Length(10), // Last Seen
    ];

    let sort_direction = if app.is_sort_ascending() {
        "↑"
    } else {
        "↓"
    };
    let title = if is_focused {
        format!(
            "PTP Hosts [FOCUSED] - Sort: {}{} (s to cycle, S to reverse)",
            sort_column.display_name(),
            sort_direction
        )
    } else {
        format!(
            "PTP Hosts - Sort: {}{} (s to cycle, S to reverse)",
            sort_column.display_name(),
            sort_direction
        )
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.as_str())
                .border_type(BorderType::Rounded)
                .border_style(if is_focused {
                    Style::default().fg(theme.border_focused)
                } else {
                    Style::default().fg(theme.border_normal)
                }),
        )
        .style(Style::default().bg(theme.background))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(">> ");

    f.render_widget(table, area);

    // Render scrollbar if needed
    if hosts.len() > visible_height {
        render_scrollbar(
            f,
            area,
            hosts.len(),
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
    let leader_count = app.ptp_tracker.get_leader_count();
    let follower_count = app.ptp_tracker.get_follower_count();

    let stats_text = vec![
        Line::from(vec![
            Span::styled("Total Hosts: ", Style::default().fg(theme.text_secondary)),
            Span::styled(
                total_hosts.to_string(),
                Style::default().fg(theme.text_primary),
            ),
        ]),
        Line::from(vec![
            Span::styled("Leaders: ", Style::default().fg(theme.text_secondary)),
            Span::styled(
                leader_count.to_string(),
                Style::default().fg(theme.state_leader),
            ),
        ]),
        Line::from(vec![
            Span::styled("Followers: ", Style::default().fg(theme.text_secondary)),
            Span::styled(
                follower_count.to_string(),
                Style::default().fg(theme.state_follower),
            ),
        ]),
        Line::from(vec![
            Span::styled("Other: ", Style::default().fg(theme.text_secondary)),
            Span::styled(
                (total_hosts - leader_count - follower_count).to_string(),
                Style::default().fg(theme.text_primary),
            ),
        ]),
        Line::from(vec![
            Span::styled("Last packet: ", Style::default().fg(theme.text_secondary)),
            Span::styled(
                format!("{}s ago", app.ptp_tracker.get_last_packet_age().as_secs()),
                Style::default().fg(theme.text_primary),
            ),
        ]),
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
    let hosts = app.get_hosts();
    let selected_index = app.get_selected_index();

    let details_text = if let Some(host) = hosts.get(selected_index) {
        vec![
            // Host details section
            Line::from(vec![
                Span::styled(
                    "Clock Identity: ",
                    Style::default().fg(theme.text_secondary),
                ),
                Span::styled(
                    host.clock_identity.clone(),
                    Style::default().fg(theme.text_primary),
                ),
                Span::styled(
                    host.get_vendor_name()
                        .map(|vendor| format!(" ({})", vendor))
                        .unwrap_or_default(),
                    Style::default().fg(theme.vendor_text),
                ),
            ]),
            Line::from(vec![
                Span::styled("IP Address: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    host.ip_address.to_string(),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
            Line::from(vec![
                Span::styled("Port: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    host.port.to_string(),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
            Line::from(vec![
                Span::styled("State: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    host.state.to_string(),
                    Style::default().fg(theme.get_state_color(&host.state)),
                ),
            ]),
            Line::from(vec![
                Span::styled("Domain: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    host.domain_number.to_string(),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
            Line::from(vec![
                Span::styled("Priority: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    host.priority1.to_string(),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
            Line::from(vec![
                Span::styled("Clock Class: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    host.clock_class.to_string(),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
            Line::from(vec![
                Span::styled("Accuracy: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    format!("0x{:02X}", host.clock_accuracy),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "Selected Leader: ",
                    Style::default().fg(theme.text_secondary),
                ),
                Span::styled(
                    host.selected_leader_id
                        .as_deref()
                        .unwrap_or("None")
                        .to_string(),
                    Style::default()
                        .fg(theme.get_confidence_color(host.selected_leader_confidence)),
                ),
                Span::styled(
                    host.selected_leader_id
                        .as_deref()
                        .and_then(|id| get_vendor_by_clock_identity(id))
                        .map(|vendor| format!(" ({})", vendor))
                        .unwrap_or_default(),
                    Style::default().fg(theme.vendor_text),
                ),
            ]),
            Line::from(vec![
                Span::styled("Domain: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    host.domain_number.to_string(),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
            Line::from(vec![
                Span::styled("Last Seen: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    format!("{:.1}s ago", host.time_since_last_seen().as_secs_f64()),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
            Line::from(vec![
                Span::styled("UTC Offset: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    host.format_utc_offset(),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "Origin Timestamp: ",
                    Style::default().fg(theme.text_secondary),
                ),
                Span::styled(
                    host.format_origin_timestamp(),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Message Counts:",
                Style::default()
                    .fg(theme.text_accent)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(vec![
                Span::styled("  Announce: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    host.announce_count.to_string(),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Sync: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    host.sync_count.to_string(),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Delay Req: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    host.delay_req_count.to_string(),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
            Line::from(vec![
                Span::styled("  Delay Resp: ", Style::default().fg(theme.text_secondary)),
                Span::styled(
                    host.delay_resp_count.to_string(),
                    Style::default().fg(theme.text_primary),
                ),
            ]),
        ]
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
    let help_text = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "PTP Network Tracer Help",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Navigation:",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  ↑/k        - Move selection up"),
        Line::from("  ↓/j        - Move selection down"),
        Line::from("  PgUp/PgDn  - Page up/down (10 items)"),
        Line::from("  Home/End   - Jump to top/bottom"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Actions:",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  r          - Refresh/rescan network"),
        Line::from("  c          - Clear all hosts"),
        Line::from("  p          - Clear packet history"),
        Line::from("  s          - Cycle host table sorting"),
        Line::from("  a          - Previous sort column"),
        Line::from("  S          - Reverse sort direction"),
        Line::from("  e          - Toggle expanded packet history"),
        Line::from("  d          - Toggle debug mode"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "General:",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  h/F1       - Show/hide this help"),
        Line::from("  q/Esc      - Quit application"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Legend:",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled("  LEAD", Style::default().fg(Color::Green)),
            Span::raw(" - PTP Leader (Grandmaster)"),
        ]),
        Line::from(vec![
            Span::styled("  FOLL", Style::default().fg(Color::Blue)),
            Span::raw(" - PTP Follower (Slave)"),
        ]),
        Line::from(vec![
            Span::styled("  LSTN", Style::default().fg(Color::Yellow)),
            Span::raw(" - Listening state"),
        ]),
        Line::from(vec![
            Span::styled("  PASV", Style::default().fg(Color::Magenta)),
            Span::raw(" - Passive state"),
        ]),
        Line::from(vec![
            Span::styled("  FALT", Style::default().fg(Color::Red)),
            Span::raw(" - Faulty state"),
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
    let theme = &app.theme;
    let packets = app.get_packet_history();
    let _scroll_offset = app.get_packet_scroll_offset();
    let total_packets = packets.len();
    let is_focused = false; // Packets are non-interactive now

    // Calculate how many packets we can display (non-interactive view)
    let content_height = area.height.saturating_sub(2) as usize; // Subtract borders
    let visible_packets = if app.is_packet_history_expanded() {
        content_height.saturating_sub(1) // Leave room for header
    } else {
        content_height.min(8).saturating_sub(1) // Limit to 8 rows when not expanded
    };

    // Create title with packet count and expansion status
    let title = if total_packets > 0 {
        let display_count = visible_packets.min(total_packets);
        let expanded_status = if app.is_packet_history_expanded() {
            " [EXPANDED]"
        } else {
            ""
        };
        format!(
            "Packet History ({}/{}) - 'e' to toggle expand{}",
            display_count, total_packets, expanded_status
        )
    } else {
        let expanded_status = if app.is_packet_history_expanded() {
            " [EXPANDED]"
        } else {
            ""
        };
        format!(
            "Packet History (No packets yet) - 'e' to toggle expand{}",
            expanded_status
        )
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(if is_focused {
            Style::default().fg(theme.border_focused)
        } else {
            Style::default().fg(theme.border_normal)
        })
        .style(Style::default().bg(theme.background));

    if packets.is_empty() {
        let no_packets_text =
            Paragraph::new("No packets captured yet. Packets will appear here as they arrive.")
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
        Cell::from("Source IP"),
        Cell::from("Port"),
        Cell::from("Interface"),
        Cell::from("Message Type"),
        Cell::from("Length"),
        Cell::from("Clock Identity"),
        Cell::from("Domain"),
        Cell::from("Seq"),
        Cell::from("Flags"),
        Cell::from("Log Interval"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    // Create table rows from packet history (newest first)
    let rows: Vec<Row> = packets
        .iter()
        .rev() // Show newest packets first
        .take(visible_packets)
        .map(|packet| {
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

            let (type_str, type_style) = match packet.message_type {
                crate::ptp::PtpMessageType::Announce => {
                    ("ANNOUNCE", Style::default().fg(Color::Green))
                }
                crate::ptp::PtpMessageType::Sync => ("SYNC", Style::default().fg(Color::Blue)),
                crate::ptp::PtpMessageType::DelayReq => {
                    ("DELAY_REQ", Style::default().fg(Color::Yellow))
                }
                crate::ptp::PtpMessageType::DelayResp => {
                    ("DELAY_RESP", Style::default().fg(Color::Cyan))
                }
                crate::ptp::PtpMessageType::FollowUp => {
                    ("FOLLOW_UP", Style::default().fg(Color::Magenta))
                }
                _ => ("OTHER", Style::default().fg(Color::Gray)),
            };

            // Truncate clock identity for better display
            let clock_display = packet.clock_identity.clone();

            Row::new(vec![
                Cell::from(time_str),
                Cell::from(packet.source_ip.clone()),
                Cell::from(packet.source_port.to_string()),
                Cell::from(packet.interface.clone()),
                Cell::from(Span::styled(type_str, type_style)),
                Cell::from(packet.message_length.to_string()),
                Cell::from(clock_display),
                Cell::from(packet.domain_number.to_string()),
                Cell::from(packet.sequence_id.to_string()),
                Cell::from(format!("{:02x}{:02x}", packet.flags[0], packet.flags[1])),
                Cell::from(packet.log_message_interval.to_string()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(10), // Time Ago
        Constraint::Length(12), // Source IP
        Constraint::Length(5),  // Port
        Constraint::Length(10), // Interface
        Constraint::Length(13), // Message Type
        Constraint::Length(6),  // Length
        Constraint::Length(22), // Clock Identity
        Constraint::Length(7),  // Domain
        Constraint::Length(5),  // Sequence
        Constraint::Length(6),  // Flags
        Constraint::Length(13), // Log Interval
    ];

    let table = Table::new(rows, widths)
        .header(headers)
        .block(block)
        .style(Style::default().bg(theme.background));

    f.render_widget(table, area);
}
