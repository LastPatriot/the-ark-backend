use std::io::Cursor;

use image::{DynamicImage, ImageFormat, Luma};
use qrcode::{EcLevel, QrCode, render::svg};

use crate::config::Config;

/// Base URL encoded in QR codes and join links. Always the mDNS name, never an IP:
/// phones keep working when the host's address changes.
pub fn public_base(cfg: &Config) -> String {
    match cfg.bind.port() {
        80 => format!("http://{}.local", cfg.hostname),
        port => format!("http://{}.local:{port}", cfg.hostname),
    }
}

pub fn svg(data: &str) -> anyhow::Result<String> {
    let code = QrCode::with_error_correction_level(data, EcLevel::M)?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(256, 256)
        .quiet_zone(true)
        .build())
}

pub fn png(data: &str) -> anyhow::Result<Vec<u8>> {
    let code = QrCode::with_error_correction_level(data, EcLevel::M)?;
    let img = code
        .render::<Luma<u8>>()
        .min_dimensions(512, 512)
        .quiet_zone(true)
        .build();
    let mut out = Cursor::new(Vec::new());
    DynamicImage::ImageLuma8(img).write_to(&mut out, ImageFormat::Png)?;
    Ok(out.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders() {
        assert!(
            svg("http://ark.local/f/sunday-service")
                .unwrap()
                .starts_with("<?xml")
        );
        assert!(
            png("http://ark.local/j/abc")
                .unwrap()
                .starts_with(b"\x89PNG")
        );
    }
}
