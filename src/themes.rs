use ratatui::style::Color;

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
    pub state_passive: Color,
    pub state_faulty: Color,
    pub state_disabled: Color,
    pub state_unknown: Color,

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

    // Status indicators
    pub confidence_high: Color,
    pub confidence_medium: Color,
    pub confidence_low: Color,
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
            state_transmitter: Color::Green,
            state_receiver: Color::Blue,
            state_listening: Color::Yellow,
            state_passive: Color::Magenta,
            state_faulty: Color::Red,
            state_disabled: Color::Gray,
            state_unknown: Color::White,

            // UI element colors
            header_fg: Color::White,
            header_bg: Color::Black,
            border_normal: Color::White,
            border_focused: Color::Green,
            text_primary: Color::White,
            text_secondary: Color::Yellow,
            text_accent: Color::Green,
            vendor_text: Color::Cyan,
            background: Color::Black,

            // Table colors
            table_header: Color::Yellow,
            sort_column_active: Color::Green,

            // Status indicators
            confidence_high: Color::Green,
            confidence_medium: Color::Yellow,
            confidence_low: Color::Red,
        }
    }

    fn monokai_theme() -> Self {
        Self {
            // PTP State colors - Monokai inspired
            state_transmitter: Color::Rgb(166, 226, 46), // Monokai green
            state_receiver: Color::Rgb(102, 217, 239),   // Monokai cyan
            state_listening: Color::Rgb(253, 151, 31),   // Monokai orange
            state_passive: Color::Rgb(174, 129, 255),    // Monokai purple
            state_faulty: Color::Rgb(249, 38, 114),      // Monokai pink/red
            state_disabled: Color::Rgb(117, 113, 94),    // Monokai gray
            state_unknown: Color::Rgb(248, 248, 242),    // Monokai white

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

            // Status indicators
            confidence_high: Color::Rgb(166, 226, 46), // Monokai green
            confidence_medium: Color::Rgb(253, 151, 31), // Monokai orange
            confidence_low: Color::Rgb(249, 38, 114),  // Monokai pink
        }
    }

    fn matrix_theme() -> Self {
        Self {
            // PTP State colors - Matrix inspired
            state_transmitter: Color::Rgb(0, 255, 65), // Bright matrix green
            state_receiver: Color::Rgb(0, 200, 50),    // Medium matrix green
            state_listening: Color::Rgb(0, 150, 35),   // Darker matrix green
            state_passive: Color::Rgb(0, 100, 25),     // Very dark matrix green
            state_faulty: Color::Rgb(255, 0, 0),       // Matrix red for errors
            state_disabled: Color::Rgb(50, 50, 50),    // Dark gray
            state_unknown: Color::Rgb(0, 180, 40),     // Matrix green variant

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

            // Status indicators
            confidence_high: Color::Rgb(0, 255, 65), // Bright matrix green
            confidence_medium: Color::Rgb(0, 200, 50), // Medium matrix green
            confidence_low: Color::Rgb(255, 0, 0),   // Matrix red
        }
    }

    pub fn get_state_color(&self, state: &crate::ptp::PtpState) -> Color {
        use crate::ptp::PtpState;
        match state {
            PtpState::Transmitter => self.state_transmitter,
            PtpState::Receiver => self.state_receiver,
            PtpState::Listening => self.state_listening,
            PtpState::Passive => self.state_passive,
            PtpState::Faulty => self.state_faulty,
            PtpState::Disabled => self.state_disabled,
            _ => self.state_unknown,
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
