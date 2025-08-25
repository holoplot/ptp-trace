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
    let (total_count, rows) = if app.tree_view_enabled {
        let hierarchical_hosts = app.get_hierarchical_hosts();
        let total_count = hierarchical_hosts.len();

        // Apply scrolling - only show visible rows
        let visible_hosts: Vec<_> = hierarchical_hosts
            .iter()
            .skip(updated_scroll_offset)
            .take(visible_height)
            .collect();

        let rows = visible_hosts.iter().enumerate().map(|(visible_i, h_host)| {
            let actual_i = visible_i + updated_scroll_offset;
            let host = h_host.host;
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

            let (_selected_transmitter_display, selected_transmitter_cell) = host
                .selected_transmitter_id
                .as_ref()
                .map(|id| {
                    // Add confidence indicator based on relationship quality
                    let (confidence_symbol, confidence_color) =
                        match host.selected_transmitter_confidence {
                            conf if conf >= 0.9 => (
                                " ✓",
                                theme.get_confidence_color(host.selected_transmitter_confidence),
                            ), // High confidence
                            conf if conf >= 0.7 => (
                                " ~",
                                theme.get_confidence_color(host.selected_transmitter_confidence),
                            ), // Good confidence
                            conf if conf >= 0.4 => (
                                " ?",
                                theme.get_confidence_color(host.selected_transmitter_confidence),
                            ), // Medium confidence
                            _ => ("", theme.text_primary), // Low/no confidence
                        };

                    let cell = Cell::from(Line::from(vec![
                        Span::styled(id.clone(), Style::default().fg(theme.text_primary)),
                        Span::styled(confidence_symbol, Style::default().fg(confidence_color)),
                    ]));
                    (format!("{}{}", id, confidence_symbol), cell)
                })
                .unwrap_or_else(|| ("-".to_string(), Cell::from("-")));

            // Format IP address display with interface info
            let ip_display = if let Some(primary_ip) = host.get_primary_ip() {
                if host.has_multiple_ips() {
                    format!("{} (+{})", primary_ip, host.get_ip_count() - 1)
                } else {
                    format!("{}", primary_ip)
                }
            } else {
                "N/A".to_string()
            };

            // Create hierarchical clock identity with tree indentation
            let tree_prefix = "`-".repeat(h_host.depth);
            let clock_identity_display = if h_host.depth > 0 {
                format!("{}{}", tree_prefix, host.clock_identity)
            } else {
                host.clock_identity.clone()
            };

            Row::new(vec![
                Cell::from({
                    let mut state_display = host.state.to_string();
                    // Add PT marker for primary time transmitter based on BMCA
                    if let Some(primary_transmitter) = app
                        .ptp_tracker
                        .get_primary_time_transmitter_for_domain(host.domain_number)
                    {
                        if host.clock_identity == primary_transmitter.clock_identity {
                            state_display = "PT".to_string();
                        }
                    }
                    // Add asterisk if this host has any local IPs
                    if host.has_local_ip(&local_ips) {
                        state_display = format!("{} *", state_display);
                    }
                    state_display
                })
                .style(Style::default().fg(state_color)),
                Cell::from(clock_identity_display),
                Cell::from(ip_display),
                Cell::from(host.domain_number.to_string()),
                Cell::from(host.priority1.map_or("-".to_string(), |p| p.to_string())),
                Cell::from(host.clock_class.map_or("-".to_string(), |c| c.to_string())),
                selected_transmitter_cell,
                Cell::from(host.total_message_count.to_string()),
                Cell::from(last_seen_str),
            ])
            .style(style)
        });

        (total_count, rows.collect())
    } else {
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

                let (_selected_transmitter_display, selected_transmitter_cell) = host
                    .selected_transmitter_id
                    .as_ref()
                    .map(|id| {
                        // Add confidence indicator based on relationship quality
                        let (confidence_symbol, confidence_color) = match host
                            .selected_transmitter_confidence
                        {
                            conf if conf >= 0.9 => (
                                " ✓",
                                theme.get_confidence_color(host.selected_transmitter_confidence),
                            ), // High confidence
                            conf if conf >= 0.7 => (
                                " ~",
                                theme.get_confidence_color(host.selected_transmitter_confidence),
                            ), // Good confidence
                            conf if conf >= 0.4 => (
                                " ?",
                                theme.get_confidence_color(host.selected_transmitter_confidence),
                            ), // Medium confidence
                            _ => ("", theme.text_primary), // Low/no confidence
                        };

                        let cell = Cell::from(Line::from(vec![
                            Span::styled(id.clone(), Style::default().fg(theme.text_primary)),
                            Span::styled(confidence_symbol, Style::default().fg(confidence_color)),
                        ]));
                        (format!("{}{}", id, confidence_symbol), cell)
                    })
                    .unwrap_or_else(|| ("-".to_string(), Cell::from("-")));

                // Format IP address display with interface info
                let ip_display = if let Some(primary_ip) = host.get_primary_ip() {
                    if host.has_multiple_ips() {
                        format!("{} (+{})", primary_ip, host.get_ip_count() - 1)
                    } else {
                        format!("{}", primary_ip)
                    }
                } else {
                    "N/A".to_string()
                };

                Row::new(vec![
                    Cell::from({
                        let mut state_display = host.state.to_string();
                        // Add PT marker for primary time transmitter based on BMCA
                        if let Some(primary_transmitter) = app
                            .ptp_tracker
                            .get_primary_time_transmitter_for_domain(host.domain_number)
                        {
                            if host.clock_identity == primary_transmitter.clock_identity {
                                state_display = "PT".to_string()
                            }
                        }
                        // Add asterisk if this host has any local IPs
                        if host.has_local_ip(&local_ips) {
                            state_display = format!("{}*", state_display);
                        }
                        state_display
                    })
                    .style(Style::default().fg(state_color)),
                    Cell::from(host.clock_identity.clone()),
                    Cell::from(ip_display),
                    Cell::from(host.domain_number.to_string()),
                    Cell::from(host.priority1.map_or("-".to_string(), |p| p.to_string())),
                    Cell::from(host.clock_class.map_or("-".to_string(), |c| c.to_string())),
                    selected_transmitter_cell,
                    Cell::from(host.total_message_count.to_string()),
                    Cell::from(last_seen_str),
                ])
                .style(style)
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

    let tree_status = if app.tree_view_enabled { " [Tree]" } else { "" };
    let title = format!(
        "PTP Hosts{} - Sort: {}{} (s to cycle, S to reverse, t for tree)",
        tree_status,
        sort_column.display_name(),
        sort_direction
    );

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
            "Other: ",
            (total_hosts - transmitter_count - receiver_count).to_string(),
            STATS_LABEL_WIDTH,
            theme,
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
        if let Some(host) = app.ptp_tracker.get_host_by_id(selected_host_id) {
            // Get local IPs for comparison
            let local_ips = app.ptp_tracker.get_local_ips();
            // Define the width for label alignment
            const LABEL_WIDTH: usize = 22; // Width for "Follow-Up Timestamp: "

            let mut details_text = vec![
                // Host details section
                create_aligned_field_with_vendor(
                    "Clock Identity: ",
                    host.clock_identity.clone(),
                    host.get_vendor_name()
                        .map(|vendor| format!(" ({})", vendor))
                        .unwrap_or_default(),
                    LABEL_WIDTH,
                    theme,
                    theme.text_primary,
                ),
            ];

            // Add IP addresses with interface info - each on its own row with "IP Address:" label
            for (ip, interface) in host.ip_addresses.iter() {
                let ip_display = if local_ips.contains(ip) {
                    format!("{} ({}) *", ip, interface)
                } else {
                    format!("{} ({})", ip, interface)
                };
                details_text.push(create_aligned_field(
                    "IP Address: ",
                    ip_display,
                    LABEL_WIDTH,
                    theme,
                ));
            }

            // Add basic fields that are always present
            details_text.push(create_aligned_field(
                "Port: ",
                host.port.to_string(),
                LABEL_WIDTH,
                theme,
            ));

            // Conditionally add version field only if it has a value
            if host.last_version.is_some() {
                details_text.push(create_aligned_field(
                    "Version: ",
                    host.get_version_string(),
                    LABEL_WIDTH,
                    theme,
                ));
            }

            details_text.extend(vec![
                create_aligned_field_with_vendor(
                    "State: ",
                    {
                        let mut state_display = host.state.full_name().to_string();
                        // Add PT marker for primary time transmitter based on BMCA
                        if let Some(primary_transmitter) = app
                            .ptp_tracker
                            .get_primary_time_transmitter_for_domain(host.domain_number)
                        {
                            if host.clock_identity == primary_transmitter.clock_identity {
                                state_display = format!("{} (Primary)", state_display);
                            }
                        }
                        state_display
                    },
                    String::new(),
                    LABEL_WIDTH,
                    theme,
                    theme.get_state_color(&host.state),
                ),
                create_aligned_field(
                    "Domain: ",
                    host.domain_number.to_string(),
                    LABEL_WIDTH,
                    theme,
                ),
            ]);

            // Conditionally add optional fields only if they have values
            if let Some(priority) = host.priority1 {
                details_text.push(create_aligned_field(
                    "Priority: ",
                    priority.to_string(),
                    LABEL_WIDTH,
                    theme,
                ));
            }

            if host.clock_class.is_some() {
                details_text.push(create_aligned_field(
                    "Clock Class: ",
                    host.format_clock_class(),
                    LABEL_WIDTH,
                    theme,
                ));
            }

            if host.clock_accuracy.is_some() {
                details_text.push(create_aligned_field(
                    "Accuracy: ",
                    host.format_clock_accuracy(),
                    LABEL_WIDTH,
                    theme,
                ));
            }

            // Always show selected transmitter field since it can show meaningful state
            if host.selected_transmitter_id.is_some() {
                details_text.push(create_aligned_field_with_vendor(
                    "Selected Transmitter: ",
                    host.selected_transmitter_id.as_deref().unwrap().to_string(),
                    host.selected_transmitter_id
                        .as_deref()
                        .and_then(|id| get_vendor_by_clock_identity(id))
                        .map(|vendor| format!(" ({})", vendor))
                        .unwrap_or_default(),
                    LABEL_WIDTH,
                    theme,
                    theme.get_confidence_color(host.selected_transmitter_confidence),
                ));
            }

            details_text.push(create_aligned_field(
                "Last Seen: ",
                format!("{:.1}s ago", host.time_since_last_seen().as_secs_f64()),
                LABEL_WIDTH,
                theme,
            ));

            if host.current_utc_offset.is_some() {
                details_text.push(create_aligned_field(
                    "UTC Offset: ",
                    host.format_utc_offset(),
                    LABEL_WIDTH,
                    theme,
                ));
            }

            if host.last_correction_field.is_some() {
                details_text.push(create_aligned_field(
                    "Correction Field: ",
                    host.get_correction_field_string(),
                    LABEL_WIDTH,
                    theme,
                ));
            }

            if host.announce_origin_timestamp.is_some() {
                details_text.push(create_aligned_field(
                    "Announce Timestamp: ",
                    host.format_announce_timestamp(),
                    LABEL_WIDTH,
                    theme,
                ));
            }

            if host.sync_origin_timestamp.is_some() {
                details_text.push(create_aligned_field(
                    "Sync Timestamp: ",
                    host.format_sync_timestamp(),
                    LABEL_WIDTH,
                    theme,
                ));
            }

            if host.followup_origin_timestamp.is_some() {
                details_text.push(create_aligned_field(
                    "Follow-Up Timestamp: ",
                    host.format_followup_timestamp(),
                    LABEL_WIDTH,
                    theme,
                ));
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
        Line::from("  ↑/k        - Move selection up"),
        Line::from("  ↓/j        - Move selection down"),
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
        Line::from("  c          - Clear all hosts and packet histories"),
        Line::from("  x          - Clear packet history for selected host"),
        Line::from("  p          - Toggle pause mode"),
        Line::from("  s          - Cycle host table sorting"),
        Line::from("  a          - Previous sort column"),
        Line::from("  S          - Reverse sort direction"),
        Line::from("  t          - Toggle tree view"),
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
                format!("  {}", crate::ptp::PtpState::Transmitter),
                Style::default().fg(theme.get_state_color(&crate::ptp::PtpState::Transmitter)),
            ),
            Span::raw(format!(
                "  - {}",
                crate::ptp::PtpState::Transmitter.full_name()
            )),
        ]),
        Line::from(vec![
            Span::styled(
                "  PT",
                Style::default().fg(theme.get_state_color(&crate::ptp::PtpState::Transmitter)),
            ),
            Span::raw(format!(
                " - {} (Primary)",
                crate::ptp::PtpState::Transmitter.full_name()
            )),
        ]),
        Line::from(vec![
            Span::styled(
                format!("  {}", crate::ptp::PtpState::Receiver),
                Style::default().fg(theme.get_state_color(&crate::ptp::PtpState::Receiver)),
            ),
            Span::raw(format!(
                "  - {}",
                crate::ptp::PtpState::Receiver.full_name()
            )),
        ]),
        Line::from(vec![
            Span::styled(
                format!("  {}", crate::ptp::PtpState::Listening),
                Style::default().fg(theme.get_state_color(&crate::ptp::PtpState::Listening)),
            ),
            Span::raw(format!(
                "  - {}",
                crate::ptp::PtpState::Listening.full_name()
            )),
        ]),
        Line::from(vec![
            Span::styled(
                format!("  {}", crate::ptp::PtpState::Passive),
                Style::default().fg(theme.get_state_color(&crate::ptp::PtpState::Passive)),
            ),
            Span::raw(format!("  - {}", crate::ptp::PtpState::Passive.full_name())),
        ]),
        Line::from(vec![
            Span::styled(
                format!("  {}", crate::ptp::PtpState::Faulty),
                Style::default().fg(theme.get_state_color(&crate::ptp::PtpState::Faulty)),
            ),
            Span::raw(format!("  - {}", crate::ptp::PtpState::Faulty.full_name())),
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
    let theme = &app.theme;
    let packets = app.get_packet_history();
    let _scroll_offset = app.get_packet_scroll_offset();
    let total_packets = packets.len();

    // Calculate how many packets we can display (non-interactive view)
    let content_height = area.height.saturating_sub(2) as usize; // Subtract borders
    let visible_packets = if app.is_packet_history_expanded() {
        content_height.saturating_sub(1) // Leave room for header
    } else {
        content_height.min(8).saturating_sub(1) // Limit to 8 rows when not expanded
    };

    // Create title with packet count, selected host info, and expansion status
    let selected_host_info = if let Some(ref host_id) = app.selected_host_id {
        format!("[{}]", &host_id[..host_id.len().min(23)]) // Truncate long clock IDs
    } else {
        "[No host selected]".to_string()
    };

    let title = if total_packets > 0 {
        let display_count = visible_packets.min(total_packets);
        let expanded_status = if app.is_packet_history_expanded() {
            " [EXPANDED]"
        } else {
            ""
        };
        format!(
            "Packet History {} ({}/{}) - 'e' to toggle expand{}",
            selected_host_info, display_count, total_packets, expanded_status
        )
    } else {
        let expanded_status = if app.is_packet_history_expanded() {
            " [EXPANDED]"
        } else {
            ""
        };
        format!(
            "Packet History{} (No packets yet) - 'e' to toggle expand{}",
            selected_host_info, expanded_status
        )
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.border_normal))
        .style(Style::default().bg(theme.background));

    if packets.is_empty() {
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
        Cell::from("Clock Identity"),
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

            // Truncate clock identity for better display
            let clock_display = packet.clock_identity.clone();

            Row::new(vec![
                Cell::from(time_str),
                Cell::from(match packet.vlan_id {
                    Some(id) => id.to_string(),
                    None => "-".to_string(),
                }),
                Cell::from(packet.source_ip.clone()),
                Cell::from(packet.source_port.to_string()),
                Cell::from(packet.interface.clone()),
                Cell::from(format!("v{}", packet.version)),
                Cell::from(Span::styled(
                    packet.message_type.to_string(),
                    theme.get_message_type_color(&packet.message_type),
                )),
                Cell::from(packet.message_length.to_string()),
                Cell::from(clock_display),
                Cell::from(packet.domain_number.to_string()),
                Cell::from(packet.sequence_id.to_string()),
                Cell::from(format!("{:02x}{:02x}", packet.flags[0], packet.flags[1])),
                Cell::from(format!(
                    "{:.02} ns",
                    (packet.correction_field as f64) / (1u64 << 16) as f64
                )),
                Cell::from(packet.log_message_interval.to_string()),
                Cell::from(packet.details.clone().unwrap_or_else(|| "-".to_string())),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(10),  // Time Ago
        Constraint::Length(5),   // VLAN
        Constraint::Length(15),  // Source IP
        Constraint::Length(5),   // Port
        Constraint::Length(10),  // Interface
        Constraint::Length(4),   // Version
        Constraint::Length(13),  // Message Type
        Constraint::Length(6),   // Length
        Constraint::Length(24),  // Clock Identity
        Constraint::Length(7),   // Domain
        Constraint::Length(5),   // Sequence
        Constraint::Length(6),   // Flags
        Constraint::Length(12),  // Correction
        Constraint::Length(9),   // Log Interval
        Constraint::Length(100), // Details
    ];

    let table = Table::new(rows, widths)
        .header(headers)
        .block(block)
        .style(Style::default().bg(theme.background));

    f.render_widget(table, area);
}
