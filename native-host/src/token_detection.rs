//! Hybrid token detection used by PING.
//!
//! PKCS#11 remains the authoritative source for signing readiness. USB probing
//! is only a fallback hint for "device likely connected" when PKCS#11 is not
//! currently usable.

use anyhow::Result;

/// Known DSC/smart-token vendors from the legacy JS host implementation.
const KNOWN_DSC_VENDOR_IDS: &[u16] = &[
    0x0BDA, 0x04E6, 0x0529, 0x096E, 0x072F, 0x0ACD, 0x076B, 0x08E6, 0x0A89, 0x0B97, 0x0BD4,
    0x0C4B, 0x0E0F, 0x10C4, 0x1FC9, 0x20A0, 0x24DF, 0x413C, 0x04CC, 0x058F, 0x062A, 0x0781,
    0x0951, 0x0BC2, 0x0EA0, 0x0FCE, 0x1050, 0x1A40, 0x1D50, 0x1E68, 0x20AD, 0x2CCF,
];

const USB_CLASS_SMART_CARD: u8 = 0x0B;

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

#[cfg(test)]
mod tests {
    use super::hybrid_token_present;
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
}
