//! AegisKey S3 High-Aesthetic Security Display UI Engine.
//!
//! Renders anti-phishing transaction screens, resident passkey confirmations,
//! OATH TOTP codes and visual hardware state onto a 320x170 RGB565 display buffer.

extern crate alloc;

use alloc::string::String;
use embedded_graphics::{
    geometry::{Point, Size},
    mono_font::{ascii::FONT_6X10, ascii::FONT_9X15_BOLD, ascii::FONT_10X20, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{Circle, PrimitiveStyle, PrimitiveStyleBuilder, Rectangle, RoundedRectangle, Line},
    text::Text,
    Drawable,
};

#[cfg(feature = "board-ttgo-classic")]
pub const DISPLAY_WIDTH: usize = 135;
#[cfg(feature = "board-ttgo-classic")]
pub const DISPLAY_HEIGHT: usize = 240;

#[cfg(not(feature = "board-ttgo-classic"))]
pub const DISPLAY_WIDTH: usize = 320;
#[cfg(not(feature = "board-ttgo-classic"))]
pub const DISPLAY_HEIGHT: usize = 170;

/// Cyber Security Color Palette (RGB565)
pub mod colors {
    use embedded_graphics::pixelcolor::Rgb565;

    pub const BG_DARK: Rgb565 = Rgb565::new(1, 3, 5);         // Deep Cyber Slate (#0B0F19)
    pub const HEADER_BG: Rgb565 = Rgb565::new(2, 6, 10);      // Slightly lighter header
    pub const ACCENT_CYAN: Rgb565 = Rgb565::new(0, 60, 31);   // Electric Neon Cyan (#00F0FF)
    pub const SUCCESS_GREEN: Rgb565 = Rgb565::new(3, 58, 12); // Emerald (#10B981)
    pub const WARN_AMBER: Rgb565 = Rgb565::new(31, 48, 2);    // Glowing Amber (#F59E0B)
    pub const DANGER_RED: Rgb565 = Rgb565::new(30, 8, 8);      // Crimson (#EF4444)
    pub const TEXT_WHITE: Rgb565 = Rgb565::new(31, 63, 31);   // Pure White
    pub const TEXT_MUTED: Rgb565 = Rgb565::new(18, 36, 18);   // Dim gray (#94A3B8)
    pub const BORDER_BOX: Rgb565 = Rgb565::new(5, 15, 20);
}

/// Screen States for AegisKey UI
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiScreen {
    BootSplash {
        version: String,
        chip: String,
    },
    IdleStandby {
        status_text: String,
    },
    UserPresencePrompt {
        rp_id: String,
        user_name: String,
        operation: String, // "Registro de Passkey" or "Autenticação FIDO2"
        remaining_seconds: u32,
    },
    Success {
        title: String,
        subtitle: String,
    },
    Error {
        message: String,
    },
    TotpCode {
        label: String,
        code: String,
        remaining_seconds: u32,
    },
}

use alloc::vec;
use alloc::vec::Vec;

/// In-memory 320x170 RGB565 Framebuffer (heap-allocated to prevent stack overflow)
pub struct DisplayBuffer {
    pub pixels: Vec<Rgb565>,
}

impl DisplayBuffer {
    pub fn new() -> Self {
        Self {
            pixels: vec![colors::BG_DARK; DISPLAY_WIDTH * DISPLAY_HEIGHT],
        }
    }

    pub fn clear(&mut self, color: Rgb565) {
        self.pixels.fill(color);
    }

    pub fn set_pixel(&mut self, x: usize, y: usize, color: Rgb565) {
        if x < DISPLAY_WIDTH && y < DISPLAY_HEIGHT {
            self.pixels[y * DISPLAY_WIDTH + x] = color;
        }
    }

    pub fn as_raw_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self.pixels.as_ptr() as *const u8,
                self.pixels.len() * core::mem::size_of::<Rgb565>(),
            )
        }
    }
}

impl embedded_graphics::draw_target::DrawTarget for DisplayBuffer {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = embedded_graphics::Pixel<Self::Color>>,
    {
        for embedded_graphics::Pixel(coord, color) in pixels.into_iter() {
            if coord.x >= 0 && coord.y >= 0 {
                let x = coord.x as usize;
                let y = coord.y as usize;
                if x < DISPLAY_WIDTH && y < DISPLAY_HEIGHT {
                    self.pixels[y * DISPLAY_WIDTH + x] = color;
                }
            }
        }
        Ok(())
    }
}

impl embedded_graphics::geometry::Dimensions for DisplayBuffer {
    fn bounding_box(&self) -> Rectangle {
        Rectangle::new(Point::zero(), Size::new(DISPLAY_WIDTH as u32, DISPLAY_HEIGHT as u32))
    }
}

/// UI Renderer for AegisKey S3
pub struct AegisUiRenderer;

impl AegisUiRenderer {
    /// Renders the specified UI Screen into the framebuffer
    pub fn render(screen: &UiScreen, target: &mut DisplayBuffer) {
        target.clear(colors::BG_DARK);

        match screen {
            UiScreen::BootSplash { version, chip } => {
                Self::draw_boot_screen(target, version, chip);
            }
            UiScreen::IdleStandby { status_text } => {
                Self::draw_idle_screen(target, status_text);
            }
            UiScreen::UserPresencePrompt {
                rp_id,
                user_name,
                operation,
                remaining_seconds,
            } => {
                Self::draw_prompt_screen(target, rp_id, user_name, operation, *remaining_seconds);
            }
            UiScreen::Success { title, subtitle } => {
                Self::draw_success_screen(target, title, subtitle);
            }
            UiScreen::Error { message } => {
                Self::draw_error_screen(target, message);
            }
            UiScreen::TotpCode { label, code, remaining_seconds } => {
                Self::draw_totp_screen(target, label, code, *remaining_seconds);
            }
        }
    }

    fn draw_header(target: &mut DisplayBuffer, title: &str, accent_color: Rgb565) {
        let h_height = if DISPLAY_HEIGHT < 150 { 20u32 } else { 24u32 };
        let header_rect = Rectangle::new(Point::new(0, 0), Size::new(DISPLAY_WIDTH as u32, h_height));
        let header_style = PrimitiveStyleBuilder::new()
            .fill_color(colors::HEADER_BG)
            .build();
        let _ = header_rect.into_styled(header_style).draw(target);

        let line = Line::new(Point::new(0, h_height as i32), Point::new(DISPLAY_WIDTH as i32, h_height as i32));
        let line_style = PrimitiveStyleBuilder::new().stroke_color(accent_color).stroke_width(2).build();
        let _ = line.into_styled(line_style).draw(target);

        let text_style = MonoTextStyle::new(&FONT_6X10, colors::TEXT_WHITE);
        let _ = Text::new(title, Point::new(8, (h_height as i32) - 6), text_style).draw(target);

        // Security indicator pill
        let pill_x = (DISPLAY_WIDTH as i32) - 50;
        let pill = Text::new("AEGIS", Point::new(pill_x, (h_height as i32) - 6), MonoTextStyle::new(&FONT_6X10, accent_color));
        let _ = pill.draw(target);
    }

    fn draw_boot_screen(target: &mut DisplayBuffer, version: &str, chip: &str) {
        let center_x = (DISPLAY_WIDTH / 2) as i32;
        let is_small = DISPLAY_HEIGHT < 150;

        let y_offset = if is_small { 24 } else { 30 };
        let s_w = if is_small { 22 } else { 30 };
        let s_h = if is_small { 50 } else { 70 };

        let p1 = Point::new(center_x, y_offset);
        let p2 = Point::new(center_x + s_w, y_offset + 14);
        let p3 = Point::new(center_x + s_w, y_offset + s_h - 14);
        let p4 = Point::new(center_x, y_offset + s_h);
        let p5 = Point::new(center_x - s_w, y_offset + s_h - 14);
        let p6 = Point::new(center_x - s_w, y_offset + 14);

        let shield_style = PrimitiveStyleBuilder::new().stroke_color(colors::ACCENT_CYAN).stroke_width(2).build();
        let _ = Line::new(p1, p2).into_styled(shield_style).draw(target);
        let _ = Line::new(p2, p3).into_styled(shield_style).draw(target);
        let _ = Line::new(p3, p4).into_styled(shield_style).draw(target);
        let _ = Line::new(p4, p5).into_styled(shield_style).draw(target);
        let _ = Line::new(p5, p6).into_styled(shield_style).draw(target);
        let _ = Line::new(p6, p1).into_styled(shield_style).draw(target);

        // Keyhole inside shield
        let key_circle = Circle::new(Point::new(center_x - 5, y_offset + 15), 10);
        let _ = key_circle.into_styled(PrimitiveStyle::with_fill(colors::ACCENT_CYAN)).draw(target);
        let key_body = Rectangle::new(Point::new(center_x - 2, y_offset + 22), Size::new(4, 12));
        let _ = key_body.into_styled(PrimitiveStyle::with_fill(colors::ACCENT_CYAN)).draw(target);

        // Title
        let title_style = MonoTextStyle::new(&FONT_9X15_BOLD, colors::TEXT_WHITE);
        let title_y = y_offset + s_h + if is_small { 16 } else { 20 };
        let _ = Text::new("AEGISKEY FIDO2", Point::new(center_x - 58, title_y), title_style).draw(target);

        // Subtitle & hardware
        let sub_style = MonoTextStyle::new(&FONT_6X10, colors::ACCENT_CYAN);
        let _ = Text::new(chip, Point::new(center_x - 60, title_y + 14), sub_style).draw(target);

        let ver_style = MonoTextStyle::new(&FONT_6X10, colors::WARN_AMBER);
        let _ = Text::new(version, Point::new(center_x - 40, title_y + 26), ver_style).draw(target);
    }

    fn draw_idle_screen(target: &mut DisplayBuffer, status_text: &str) {
        Self::draw_header(target, "AEGISKEY • PRONTO", colors::ACCENT_CYAN);

        let center_x = (DISPLAY_WIDTH / 2) as i32;
        let is_small = DISPLAY_HEIGHT < 150;

        // Big Lock Circle
        let circle_r = if is_small { 36 } else { 50 };
        let circle_y = if is_small { 28 } else { 45 };
        let lock_circle = Circle::new(Point::new(center_x - (circle_r / 2), circle_y), circle_r as u32);
        let circle_style = PrimitiveStyleBuilder::new()
            .stroke_color(colors::ACCENT_CYAN)
            .stroke_width(2)
            .build();
        let _ = lock_circle.into_styled(circle_style).draw(target);

        // Center status
        let main_style = MonoTextStyle::new(&FONT_9X15_BOLD, colors::TEXT_WHITE);
        let main_y = circle_y + circle_r + if is_small { 18 } else { 25 };
        let _ = Text::new("DISPOSITIVO ATIVO", Point::new(center_x - 70, main_y), main_style).draw(target);

        let sub_style = MonoTextStyle::new(&FONT_6X10, colors::TEXT_MUTED);
        let _ = Text::new(status_text, Point::new(center_x - 85, main_y + 14), sub_style).draw(target);

        // Footer USB Ready indicator
        let footer_h = if is_small { 16u32 } else { 18u32 };
        let footer_y = (DISPLAY_HEIGHT as i32) - (footer_h as i32);
        let footer_rect = Rectangle::new(Point::new(0, footer_y), Size::new(DISPLAY_WIDTH as u32, footer_h));
        let footer_style = PrimitiveStyle::with_fill(colors::HEADER_BG);
        let _ = footer_rect.into_styled(footer_style).draw(target);

        let ok_dot = Circle::new(Point::new(8, footer_y + 4), 8);
        let _ = ok_dot.into_styled(PrimitiveStyle::with_fill(colors::SUCCESS_GREEN)).draw(target);

        let usb_style = MonoTextStyle::new(&FONT_6X10, colors::SUCCESS_GREEN);
        let _ = Text::new("CTAPHID / WebAuthn Online", Point::new(20, footer_y + 11), usb_style).draw(target);
    }

    fn draw_prompt_screen(
        target: &mut DisplayBuffer,
        rp_id: &str,
        user_name: &str,
        operation: &str,
        remaining_seconds: u32,
    ) {
        Self::draw_header(target, "SOLICITAÇÃO DE PRESENÇA", colors::WARN_AMBER);

        let is_small = DISPLAY_HEIGHT < 150;
        let mut y = if is_small { 30 } else { 38 };

        // Operation type (e.g. Registro de Passkey / Login)
        let op_style = MonoTextStyle::new(&FONT_6X10, colors::WARN_AMBER);
        let _ = Text::new(operation, Point::new(10, y), op_style).draw(target);
        y += 10;

        // Anti-phishing Domain Highlight Box
        let box_w = (DISPLAY_WIDTH as u32) - 20;
        let box_h = if is_small { 24u32 } else { 32u32 };
        let box_rect = RoundedRectangle::with_equal_corners(
            Rectangle::new(Point::new(10, y), Size::new(box_w, box_h)),
            Size::new(4, 4),
        );
        let box_style = PrimitiveStyleBuilder::new()
            .fill_color(colors::BORDER_BOX)
            .stroke_color(colors::WARN_AMBER)
            .stroke_width(2)
            .build();
        let _ = box_rect.into_styled(box_style).draw(target);

        // RP Domain Name in bold
        let domain_style = MonoTextStyle::new(&FONT_9X15_BOLD, colors::TEXT_WHITE);
        let _ = Text::new(rp_id, Point::new(18, y + (box_h as i32) - 8), domain_style).draw(target);
        y += (box_h as i32) + 12;

        // Account Name
        let user_label_style = MonoTextStyle::new(&FONT_6X10, colors::TEXT_MUTED);
        let _ = Text::new("Conta:", Point::new(10, y), user_label_style).draw(target);

        let user_val_style = MonoTextStyle::new(&FONT_6X10, colors::ACCENT_CYAN);
        let _ = Text::new(user_name, Point::new(50, y), user_val_style).draw(target);
        y += 14;

        // Call to action button instructions
        #[cfg(any(feature = "board-t-display", feature = "board-ttgo-classic"))]
        {
            let confirm_style = MonoTextStyle::new(&FONT_6X10, colors::SUCCESS_GREEN);
            let _ = Text::new("BOOT: Confirmar", Point::new(10, y), confirm_style).draw(target);

            let cancel_style = MonoTextStyle::new(&FONT_6X10, colors::DANGER_RED);
            #[cfg(feature = "board-ttgo-classic")]
            let cancel_str = "KEY: Cancelar";
            #[cfg(not(feature = "board-ttgo-classic"))]
            let cancel_str = "KEY: Cancelar";
            let _ = Text::new(cancel_str, Point::new((DISPLAY_WIDTH as i32) - 95, y), cancel_style).draw(target);
        }
        #[cfg(not(any(feature = "board-t-display", feature = "board-ttgo-classic")))]
        {
            let prompt_style = MonoTextStyle::new(&FONT_9X15_BOLD, colors::SUCCESS_GREEN);
            let _ = Text::new("👉 Pressione BOOT", Point::new(20, y), prompt_style).draw(target);
        }
        y += 10;

        // Countdown Bar
        let bar_width = (DISPLAY_WIDTH as u32) - 20;
        let progress = (remaining_seconds.min(25) as f32 / 25.0).clamp(0.0, 1.0);
        let fill_w = (bar_width as f32 * progress) as u32;

        let bar_bg = Rectangle::new(Point::new(10, y), Size::new(bar_width, 6));
        let _ = bar_bg.into_styled(PrimitiveStyle::with_fill(colors::HEADER_BG)).draw(target);

        if fill_w > 0 {
            let bar_fill = Rectangle::new(Point::new(10, y), Size::new(fill_w, 6));
            let fill_color = if remaining_seconds > 10 {
                colors::ACCENT_CYAN
            } else if remaining_seconds > 5 {
                colors::WARN_AMBER
            } else {
                colors::DANGER_RED
            };
            let _ = bar_fill.into_styled(PrimitiveStyle::with_fill(fill_color)).draw(target);
        }

        // Remaining text
        let rem_text = alloc::format!("{}s", remaining_seconds);
        let rem_style = MonoTextStyle::new(&FONT_6X10, colors::TEXT_MUTED);
        let _ = Text::new(&rem_text, Point::new((DISPLAY_WIDTH as i32) - 28, y + 14), rem_style).draw(target);
    }

    fn draw_success_screen(target: &mut DisplayBuffer, title: &str, subtitle: &str) {
        Self::draw_header(target, "AUTORIZAÇÃO CONFIRMADA", colors::SUCCESS_GREEN);

        let center_x = (DISPLAY_WIDTH / 2) as i32;
        let is_small = DISPLAY_HEIGHT < 150;

        let circle_r = if is_small { 44 } else { 60 };
        let circle_y = if is_small { 28 } else { 38 };
        let check_circle = Circle::new(Point::new(center_x - (circle_r / 2), circle_y), circle_r as u32);
        let circle_style = PrimitiveStyle::with_fill(colors::SUCCESS_GREEN);
        let _ = check_circle.into_styled(circle_style).draw(target);

        // Draw Checkmark lines
        let p_start = Point::new(center_x - 12, circle_y + (circle_r / 2));
        let p_mid = Point::new(center_x - 3, circle_y + (circle_r / 2) + 8);
        let p_end = Point::new(center_x + 14, circle_y + (circle_r / 2) - 8);

        let check_style = PrimitiveStyleBuilder::new()
            .stroke_color(colors::BG_DARK)
            .stroke_width(3)
            .build();
        let _ = Line::new(p_start, p_mid).into_styled(check_style).draw(target);
        let _ = Line::new(p_mid, p_end).into_styled(check_style).draw(target);

        let title_style = MonoTextStyle::new(&FONT_9X15_BOLD, colors::TEXT_WHITE);
        let text_y = circle_y + circle_r + if is_small { 18 } else { 24 };
        let _ = Text::new(title, Point::new(center_x - 65, text_y), title_style).draw(target);

        let sub_style = MonoTextStyle::new(&FONT_6X10, colors::SUCCESS_GREEN);
        let _ = Text::new(subtitle, Point::new(center_x - 80, text_y + 14), sub_style).draw(target);
    }

    fn draw_error_screen(target: &mut DisplayBuffer, message: &str) {
        Self::draw_header(target, "FALHA / CANCELADO", colors::DANGER_RED);

        let center_x = (DISPLAY_WIDTH / 2) as i32;
        let is_small = DISPLAY_HEIGHT < 150;

        let circle_r = if is_small { 44 } else { 60 };
        let circle_y = if is_small { 28 } else { 38 };
        let cross_circle = Circle::new(Point::new(center_x - (circle_r / 2), circle_y), circle_r as u32);
        let circle_style = PrimitiveStyle::with_fill(colors::DANGER_RED);
        let _ = cross_circle.into_styled(circle_style).draw(target);

        // Cross lines
        let cross_style = PrimitiveStyleBuilder::new()
            .stroke_color(colors::BG_DARK)
            .stroke_width(3)
            .build();
        let _ = Line::new(Point::new(center_x - 10, circle_y + 12), Point::new(center_x + 10, circle_y + circle_r - 12))
            .into_styled(cross_style)
            .draw(target);
        let _ = Line::new(Point::new(center_x + 10, circle_y + 12), Point::new(center_x - 10, circle_y + circle_r - 12))
            .into_styled(cross_style)
            .draw(target);

        let err_style = MonoTextStyle::new(&FONT_9X15_BOLD, colors::TEXT_WHITE);
        let text_y = circle_y + circle_r + if is_small { 18 } else { 24 };
        let _ = Text::new("OPERAÇÃO RECUSADA", Point::new(center_x - 75, text_y), err_style).draw(target);

        let sub_style = MonoTextStyle::new(&FONT_6X10, colors::DANGER_RED);
        let _ = Text::new(message, Point::new(center_x - 80, text_y + 14), sub_style).draw(target);
    }

    fn draw_totp_screen(target: &mut DisplayBuffer, label: &str, code: &str, remaining_seconds: u32) {
        Self::draw_header(target, "YKOATH / TOTP 2FA", colors::ACCENT_CYAN);

        let center_x = (DISPLAY_WIDTH / 2) as i32;
        let is_small = DISPLAY_HEIGHT < 150;

        let label_style = MonoTextStyle::new(&FONT_6X10, colors::TEXT_MUTED);
        let _ = Text::new(label, Point::new(center_x - 50, if is_small { 34 } else { 42 }), label_style).draw(target);

        // Code box
        let box_w = (DISPLAY_WIDTH as u32) - 40;
        let box_h = if is_small { 32u32 } else { 45u32 };
        let box_y = if is_small { 42 } else { 55 };
        let code_box = RoundedRectangle::with_equal_corners(
            Rectangle::new(Point::new(20, box_y), Size::new(box_w, box_h)),
            Size::new(6, 6),
        );
        let box_style = PrimitiveStyleBuilder::new()
            .fill_color(colors::BORDER_BOX)
            .stroke_color(colors::ACCENT_CYAN)
            .stroke_width(2)
            .build();
        let _ = code_box.into_styled(box_style).draw(target);

        let code_style = MonoTextStyle::new(&FONT_10X20, colors::ACCENT_CYAN);
        let _ = Text::new(code, Point::new(center_x - 45, box_y + (box_h as i32) - 8), code_style).draw(target);

        // Progress bar for 30s token expiration
        let bar_width = (DISPLAY_WIDTH as u32) - 40;
        let progress = (remaining_seconds.min(30) as f32 / 30.0).clamp(0.0, 1.0);
        let fill_w = (bar_width as f32 * progress) as u32;

        let bar_y = box_y + (box_h as i32) + 8;
        let bar_bg = Rectangle::new(Point::new(20, bar_y), Size::new(bar_width, 6));
        let _ = bar_bg.into_styled(PrimitiveStyle::with_fill(colors::HEADER_BG)).draw(target);

        if fill_w > 0 {
            let bar_fill = Rectangle::new(Point::new(20, bar_y), Size::new(fill_w, 6));
            let _ = bar_fill.into_styled(PrimitiveStyle::with_fill(colors::ACCENT_CYAN)).draw(target);
        }

        let hint_style = MonoTextStyle::new(&FONT_6X10, colors::TEXT_WHITE);
        let _ = Text::new("BOOT (2s) Auto-Digita", Point::new(center_x - 65, bar_y + 16), hint_style).draw(target);

        let sec_text = alloc::format!("{}s", remaining_seconds);
        let sec_style = MonoTextStyle::new(&FONT_6X10, colors::TEXT_MUTED);
        let _ = Text::new(&sec_text, Point::new((DISPLAY_WIDTH as i32) - 35, bar_y + 16), sec_style).draw(target);
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_all_screens() {
        let mut buffer = DisplayBuffer::new();

        // 1. Boot Screen
        let boot = UiScreen::BootSplash {
            version: "v1.0.0-rust".into(),
            chip: "ESP32-S3 Dual-Core".into(),
        };
        AegisUiRenderer::render(&boot, &mut buffer);
        assert_eq!(buffer.pixels.len(), DISPLAY_WIDTH * DISPLAY_HEIGHT);

        // 2. Idle Standby Screen
        let idle = UiScreen::IdleStandby {
            status_text: "Aguardando solicitação FIDO2...".into(),
        };
        AegisUiRenderer::render(&idle, &mut buffer);

        // 3. Prompt Screen (Anti-Phishing)
        let prompt = UiScreen::UserPresencePrompt {
            rp_id: "passkey2.com".into(),
            user_name: "junior@aegiskey.dev".into(),
            operation: "Registro de Passkey".into(),
            remaining_seconds: 25,
        };
        AegisUiRenderer::render(&prompt, &mut buffer);

        // 4. Success Screen
        let success = UiScreen::Success {
            title: "ACESSO AUTORIZADO".into(),
            subtitle: "Passkey gerada com sucesso".into(),
        };
        AegisUiRenderer::render(&success, &mut buffer);

        // 5. Error Screen
        let err = UiScreen::Error {
            message: "Toque cancelado pelo usuário".into(),
        };
        AegisUiRenderer::render(&err, &mut buffer);

        // 6. TOTP Screen
        let totp = UiScreen::TotpCode {
            label: "GitHub: junior".into(),
            code: "839 204".into(),
            remaining_seconds: 28,
        };
        AegisUiRenderer::render(&totp, &mut buffer);
    }
}

