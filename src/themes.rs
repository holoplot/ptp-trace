use ratatui::style::Color;

use crate::{ptp::PtpHostState, types::PtpMessageType};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThemeName {
    Default,
    Monokai,
    Matrix,
}

impl ThemeName {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "default" => Some(Self::Default),
            "monokai" => Some(Self::Monokai),
            "matrix" => Some(Self::Matrix),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Monokai => "monokai",
            Self::Matrix => "matrix",
        }
    }

    pub fn all_themes() -> &'static [ThemeName] {
        &[ThemeName::Default, ThemeName::Monokai, ThemeName::Matrix]
    }
}

#[derive(Debug, Clone)]
pub struct Theme {
    // PTP State colors
    pub state_transmitter: Color,
    pub state_receiver: Color,
    pub state_listening: Color,

    // UI element colors
    pub header_fg: Color,
    pub header_bg: Color,
    pub border_normal: Color,
    pub border_focused: Color,
    pub text_primary: Color,
    pub text_secondary: Color,
    pub text_accent: Color,
    pub vendor_text: Color,
    pub background: Color,

    // Table colors
    pub table_header: Color,
    pub sort_column_active: Color,
    pub selected_row_background: Color,

    // Status indicators
    pub confidence_high: Color,
    pub confidence_medium: Color,
    pub confidence_low: Color,

    // Packet type colors
    pub message_type_sync: Color,
    pub message_type_follow_up: Color,
    pub message_type_delay_req: Color,
    pub message_type_delay_resp: Color,
    pub message_type_pdelay_req: Color,
    pub message_type_pdelay_resp: Color,
    pub message_type_pdelay_resp_follow_up: Color,
    pub message_type_unknown: Color,
}

impl Theme {
    pub fn new(theme_name: ThemeName) -> Self {
        match theme_name {
            ThemeName::Default => Self::default_theme(),
            ThemeName::Monokai => Self::monokai_theme(),
            ThemeName::Matrix => Self::matrix_theme(),
        }
    }

    fn default_theme() -> Self {
        Self {
            // PTP State colors
            state_transmitter: Color::Rgb(46, 204, 113), // Emerald green
            state_receiver: Color::Rgb(52, 152, 219),    // Dodger blue
            state_listening: Color::Rgb(241, 196, 15),   // Sun flower yellow

            // UI element colors
            header_fg: Color::Rgb(236, 240, 241), // Clouds white
            header_bg: Color::Rgb(0, 0, 0),       // Midnight blue
            border_normal: Color::Rgb(149, 165, 166), // Concrete gray
            border_focused: Color::Rgb(46, 204, 113), // Emerald green
            text_primary: Color::Rgb(236, 240, 241), // Clouds white
            text_secondary: Color::Rgb(189, 195, 199), // Silver
            text_accent: Color::Rgb(46, 204, 113), // Emerald green
            vendor_text: Color::Rgb(26, 188, 156), // Turquoise
            background: Color::Rgb(0, 0, 0),      // Midnight blue

            // Table colors
            table_header: Color::Rgb(52, 152, 219), // Dodger blue
            sort_column_active: Color::Rgb(46, 204, 113), // Emerald green
            selected_row_background: Color::DarkGray,

            // Status indicators
            confidence_high: Color::Rgb(46, 204, 113), // Emerald green
            confidence_medium: Color::Rgb(241, 196, 15), // Sun flower yellow
            confidence_low: Color::Rgb(231, 76, 60),   // Alizarin red

            // Packet type colors
            message_type_sync: Color::Rgb(46, 204, 113), // Emerald green
            message_type_follow_up: Color::Rgb(52, 152, 219), // Dodger blue
            message_type_delay_req: Color::Rgb(241, 196, 15), // Sun flower yellow
            message_type_delay_resp: Color::Rgb(155, 89, 182), // Amethyst purple
            message_type_pdelay_req: Color::Rgb(231, 76, 60), // Alizarin red
            message_type_pdelay_resp: Color::Rgb(149, 165, 166), // Concrete gray
            message_type_pdelay_resp_follow_up: Color::Rgb(26, 188, 156), // Turquoise
            message_type_unknown: Color::Rgb(236, 240, 241), // Clouds white
        }
    }

    fn monokai_theme() -> Self {
        Self {
            // PTP State colors - Monokai inspired
            state_transmitter: Color::Rgb(166, 226, 46), // Monokai green
            state_receiver: Color::Rgb(102, 217, 239),   // Monokai cyan
            state_listening: Color::Rgb(253, 151, 31),   // Monokai orange

            // UI element colors - Monokai inspired
            header_fg: Color::Rgb(248, 248, 242), // Monokai white
            header_bg: Color::Rgb(39, 40, 34),    // Monokai dark bg
            border_normal: Color::Rgb(117, 113, 94), // Monokai gray
            border_focused: Color::Rgb(166, 226, 46), // Monokai green
            text_primary: Color::Rgb(248, 248, 242), // Monokai white
            text_secondary: Color::Rgb(253, 151, 31), // Monokai orange
            text_accent: Color::Rgb(166, 226, 46), // Monokai green
            vendor_text: Color::Rgb(102, 217, 239), // Monokai cyan
            background: Color::Rgb(39, 40, 34),   // Monokai dark bg

            // Table colors
            table_header: Color::Rgb(253, 151, 31), // Monokai orange
            sort_column_active: Color::Rgb(166, 226, 46), // Monokai green
            selected_row_background: Color::DarkGray,

            // Status indicators
            confidence_high: Color::Rgb(166, 226, 46), // Monokai green
            confidence_medium: Color::Rgb(253, 151, 31), // Monokai orange
            confidence_low: Color::Rgb(249, 38, 114),  // Monokai pink

            // Packet type colors
            message_type_sync: Color::Rgb(166, 226, 46), // Monokai green
            message_type_follow_up: Color::Rgb(102, 217, 239), // Monokai cyan
            message_type_delay_req: Color::Rgb(253, 151, 31), // Monokai orange
            message_type_delay_resp: Color::Rgb(174, 129, 255), // Monokai purple
            message_type_pdelay_req: Color::Rgb(249, 38, 114), // Monokai pink/red
            message_type_pdelay_resp: Color::Rgb(117, 113, 94), // Monokai gray
            message_type_pdelay_resp_follow_up: Color::Rgb(248, 248, 242), // Monokai white
            message_type_unknown: Color::Rgb(248, 248, 242), // Monokai white
        }
    }

    fn matrix_theme() -> Self {
        Self {
            // PTP State colors - Matrix inspired
            state_transmitter: Color::Rgb(0, 255, 65), // Bright matrix green
            state_receiver: Color::Rgb(0, 200, 50),    // Medium matrix green
            state_listening: Color::Rgb(0, 150, 35),   // Darker matrix green

            // UI element colors - Matrix inspired
            header_fg: Color::Rgb(0, 255, 65), // Bright matrix green
            header_bg: Color::Rgb(0, 0, 0),    // Pure black
            border_normal: Color::Rgb(0, 150, 35), // Medium matrix green
            border_focused: Color::Rgb(0, 255, 65), // Bright matrix green
            text_primary: Color::Rgb(0, 200, 50), // Matrix green
            text_secondary: Color::Rgb(0, 150, 35), // Darker matrix green
            text_accent: Color::Rgb(0, 255, 65), // Bright matrix green
            vendor_text: Color::Rgb(0, 180, 40), // Matrix green variant
            background: Color::Rgb(0, 0, 0),   // Pure black

            // Table colors
            table_header: Color::Rgb(0, 255, 65), // Bright matrix green
            sort_column_active: Color::Rgb(0, 255, 65), // Bright matrix green
            selected_row_background: Color::DarkGray,

            // Status indicators
            confidence_high: Color::Rgb(0, 255, 65), // Bright matrix green
            confidence_medium: Color::Rgb(0, 200, 50), // Medium matrix green
            confidence_low: Color::Rgb(255, 0, 0),   // Matrix red

            // Packet type colors
            message_type_sync: Color::Rgb(0, 255, 65), // Bright matrix green
            message_type_follow_up: Color::Rgb(0, 200, 50), // Medium matrix green
            message_type_delay_req: Color::Rgb(0, 180, 40), // Matrix green variant
            message_type_delay_resp: Color::Rgb(0, 150, 35), // Darker matrix green
            message_type_pdelay_req: Color::Rgb(0, 255, 100), // Light matrix green
            message_type_pdelay_resp: Color::Rgb(0, 120, 30), // Dark matrix green
            message_type_pdelay_resp_follow_up: Color::Rgb(0, 220, 55), // Matrix green variant
            message_type_unknown: Color::Rgb(0, 100, 25), // Very dark matrix green
        }
    }

    pub fn get_state_color(&self, state: &crate::ptp::PtpHostState) -> Color {
        match state {
            PtpHostState::TimeTransmitter(_) => self.state_transmitter,
            PtpHostState::TimeReceiver(_) => self.state_receiver,
            PtpHostState::Listening => self.state_listening,
        }
    }

    pub fn get_message_type_color(&self, message_type: &PtpMessageType) -> Color {
        match message_type {
            PtpMessageType::Sync => self.message_type_sync,
            PtpMessageType::FollowUp => self.message_type_follow_up,
            PtpMessageType::DelayReq => self.message_type_delay_req,
            PtpMessageType::DelayResp => self.message_type_delay_resp,
            PtpMessageType::PDelayReq => self.message_type_pdelay_req,
            PtpMessageType::PDelayResp => self.message_type_pdelay_resp,
            PtpMessageType::PDelayRespFollowUp => self.message_type_pdelay_resp_follow_up,
            _ => self.message_type_unknown,
        }
    }

    pub fn get_confidence_color(&self, confidence: f32) -> Color {
        match confidence {
            conf if conf >= 0.9 => self.confidence_high,
            conf if conf >= 0.7 => self.confidence_medium,
            _ => self.confidence_low,
        }
    }
}

impl Default for Theme {
    fn default() -> Self {
        Self::new(ThemeName::Default)
    }
}
