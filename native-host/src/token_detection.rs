//! Hybrid token detection used by PING.
//!
//! PKCS#11 remains the authoritative source for signing readiness. USB probing
//! is only a fallback hint for "device likely connected" when PKCS#11 is not
//! currently usable.

use anyhow::Result;
use serde::Serialize;

/// Known DSC/smart-token vendors from the legacy JS host implementation.
const KNOWN_DSC_VENDOR_IDS: &[u16] = &[
    0x0BDA, 0x04E6, 0x0529, 0x096E, 0x072F, 0x0ACD, 0x076B, 0x08E6, 0x0A89, 0x0B97, 0x0BD4,
    0x0C4B, 0x0E0F, 0x10C4, 0x1FC9, 0x20A0, 0x24DF, 0x413C, 0x04CC, 0x058F, 0x062A, 0x0781,
    0x0951, 0x0BC2, 0x0EA0, 0x0FCE, 0x1050, 0x1A40, 0x1D50, 0x1E68, 0x20AD, 0x2CCF,
];

const USB_CLASS_SMART_CARD: u8 = 0x0B;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UsbTokenInfo {
    pub id: String,
    pub label: String,
    pub manufacturer: Option<String>,
    pub serial: Option<String>,
    pub path: String,
}

/// Hybrid detector:
/// - `true` if PKCS#11 reports token-present slots.
/// - otherwise, `true` if USB heuristics detect a likely token.
/// - never errors; caller receives a best-effort boolean.
pub fn hybrid_token_present(
    pkcs11_probe: impl FnOnce() -> Result<bool>,
    usb_probe: impl FnOnce() -> bool,
) -> bool {
    tracing::debug!("PING token detection: starting hybrid probe");
    match pkcs11_probe() {
        Ok(true) => {
            tracing::debug!("PING token detection: PKCS#11 probe reported token present");
            true
        }
        Ok(false) => {
            let usb = usb_probe();
            if usb {
                tracing::debug!("PING token detection: PKCS#11 empty, USB fallback matched");
            } else {
                tracing::debug!("PING token detection: PKCS#11 empty, USB fallback not matched");
            }
            usb
        }
        Err(e) => {
            tracing::warn!("PING token detection: PKCS#11 probe failed, trying USB fallback: {e:?}");
            let usb = usb_probe();
            tracing::debug!(usb, "PING token detection: USB fallback result after PKCS#11 failure");
            usb
        }
    }
}

/// Best-effort USB hint probe (does not guarantee signability).
pub fn usb_token_hint_present() -> bool {
    let devices = match rusb::devices() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("USB enumeration failed during token hint probe: {e}");
            return false;
        }
    };

    for device in devices.iter() {
        let descriptor = match device.device_descriptor() {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!("Skipping USB device with unreadable descriptor: {e}");
                continue;
            }
        };

        if KNOWN_DSC_VENDOR_IDS.contains(&descriptor.vendor_id()) {
            tracing::debug!(
                vendor_id = descriptor.vendor_id(),
                product_id = descriptor.product_id(),
                "USB token hint matched known DSC vendor"
            );
            return true;
        }

        if descriptor.class_code() == USB_CLASS_SMART_CARD {
            tracing::debug!(
                vendor_id = descriptor.vendor_id(),
                product_id = descriptor.product_id(),
                "USB token hint matched smart-card device class"
            );
            return true;
        }

        if let Ok(config) = device.active_config_descriptor() {
            for interface in config.interfaces() {
                for iface_descriptor in interface.descriptors() {
                    if iface_descriptor.class_code() == USB_CLASS_SMART_CARD {
                        tracing::debug!(
                            vendor_id = descriptor.vendor_id(),
                            product_id = descriptor.product_id(),
                            "USB token hint matched smart-card interface class"
                        );
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Enumerates USB tokens using vendor/class heuristics only.
/// This intentionally avoids PKCS#11 for discovery.
pub fn list_usb_tokens() -> Result<Vec<UsbTokenInfo>> {
    tracing::info!("USB token listing: starting enumeration");
    let devices = rusb::devices()?;
    let mut tokens = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for device in devices.iter() {
        let descriptor = match device.device_descriptor() {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!("USB token listing: skipping unreadable descriptor: {e}");
                continue;
            }
        };

        let mut matched_reason = classify_device(
            descriptor.vendor_id(),
            descriptor.class_code(),
            descriptor.sub_class_code(),
            descriptor.protocol_code(),
            false,
        );

        if matched_reason.is_none() {
            if let Ok(config) = device.active_config_descriptor() {
                for interface in config.interfaces() {
                    for iface_descriptor in interface.descriptors() {
                        matched_reason = classify_device(
                            descriptor.vendor_id(),
                            descriptor.class_code(),
                            descriptor.sub_class_code(),
                            descriptor.protocol_code(),
                            iface_descriptor.class_code() == USB_CLASS_SMART_CARD,
                        );
                        if matched_reason.is_some() {
                            break;
                        }
                    }
                    if matched_reason.is_some() {
                        break;
                    }
                }
            }
        }

        let Some(reason) = matched_reason else {
            tracing::debug!(
                vendor_id = descriptor.vendor_id(),
                product_id = descriptor.product_id(),
                bus = device.bus_number(),
                address = device.address(),
                "USB token listing: device ignored (no token heuristic match)"
            );
            continue;
        };

        let bus = device.bus_number();
        let address = device.address();
        let id = format!(
            "{:04x}:{:04x}-{}-{}",
            descriptor.vendor_id(),
            descriptor.product_id(),
            bus,
            address
        );

        if !seen.insert(id.clone()) {
            continue;
        }

        let mut manufacturer = None;
        let mut serial = None;
        if let Ok(handle) = device.open() {
            manufacturer = handle.read_manufacturer_string_ascii(&descriptor).ok();
            serial = handle.read_serial_number_string_ascii(&descriptor).ok();
        }

        let label = format!(
            "USB Token {:04X}:{:04X}",
            descriptor.vendor_id(),
            descriptor.product_id()
        );
        let path = format!("usb:{}:{}", bus, address);

        tracing::info!(
            token_id = %id,
            vendor_id = descriptor.vendor_id(),
            product_id = descriptor.product_id(),
            bus,
            address,
            reason,
            has_manufacturer = manufacturer.is_some(),
            has_serial = serial.is_some(),
            "USB token listing: matched token device"
        );

        tokens.push(UsbTokenInfo {
            id,
            label,
            manufacturer,
            serial,
            path,
        });
    }

    tracing::info!(token_count = tokens.len(), "USB token listing: completed enumeration");
    Ok(tokens)
}

fn classify_device(
    vendor_id: u16,
    class_code: u8,
    sub_class_code: u8,
    protocol_code: u8,
    has_smart_card_interface: bool,
) -> Option<&'static str> {
    if KNOWN_DSC_VENDOR_IDS.contains(&vendor_id) {
        return Some("known_vendor");
    }
    if class_code == USB_CLASS_SMART_CARD {
        return Some("device_class_smart_card");
    }
    // Keep some room for future tunings when vendors expose composite devices.
    if has_smart_card_interface {
        return Some("interface_class_smart_card");
    }
    tracing::trace!(
        vendor_id,
        class_code,
        sub_class_code,
        protocol_code,
        "USB token listing: non-matching USB descriptor observed"
    );
    None
}

#[cfg(test)]
mod tests {
    use super::{classify_device, hybrid_token_present, KNOWN_DSC_VENDOR_IDS, USB_CLASS_SMART_CARD};
    use anyhow::anyhow;

    #[test]
    fn hybrid_returns_true_when_pkcs11_true() {
        let value = hybrid_token_present(|| Ok(true), || false);
        assert!(value);
    }

    #[test]
    fn hybrid_uses_usb_when_pkcs11_false() {
        let value = hybrid_token_present(|| Ok(false), || true);
        assert!(value);
    }

    #[test]
    fn hybrid_uses_usb_when_pkcs11_errors() {
        let value = hybrid_token_present(|| Err(anyhow!("pkcs11 failed")), || false);
        assert!(!value);
    }

    #[test]
    fn classify_matches_known_vendor() {
        let vendor = KNOWN_DSC_VENDOR_IDS[0];
        let reason = classify_device(vendor, 0, 0, 0, false);
        assert_eq!(reason, Some("known_vendor"));
    }

    #[test]
    fn classify_matches_smart_card_class() {
        let reason = classify_device(0xFFFF, USB_CLASS_SMART_CARD, 0, 0, false);
        assert_eq!(reason, Some("device_class_smart_card"));
    }

    #[test]
    fn classify_matches_smart_card_interface() {
        let reason = classify_device(0xFFFF, 0, 0, 0, true);
        assert_eq!(reason, Some("interface_class_smart_card"));
    }

    #[test]
    fn classify_rejects_unknown_non_smart_card_devices() {
        let reason = classify_device(0xFFFF, 0, 0, 0, false);
        assert_eq!(reason, None);
    }
}
