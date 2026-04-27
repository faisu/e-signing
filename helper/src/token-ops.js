'use strict';
/**
 * High-level token operations built on top of graphene-pk11.
 * graphene-pk11 wraps libpkcs11 / cryptoki with a JS API.
 */

const { MechanismEnum, KeyType, ObjectClass, SessionFlag } = require('graphene-pk11');
const forge = require('node-forge');

/**
 * List all certificates from all slots that have a token present.
 * Returns objects compatible with the DscCertificate TypeScript type.
 *
 * @param {import('graphene-pk11').Module} lib
 * @returns {Array}
 */
function listCertificates(lib) {
  const results = [];

  for (const slot of lib.getSlots(true)) {
    let session;
    try {
      session = slot.open(SessionFlag.RO_SESSION | SessionFlag.SERIAL_SESSION);
      const certs = session.find({ class: ObjectClass.CERTIFICATE });

      for (const certObj of certs) {
        try {
          const x509Buf = Buffer.from(certObj.getAttribute({ value: null }).value);
          const cert = forge.pki.certificateFromDer(forge.util.createBuffer(x509Buf));

          const keyUsageExt = cert.getExtension('keyUsage');
          const keyUsage = [];
          if (keyUsageExt) {
            if (keyUsageExt.digitalSignature) keyUsage.push('digitalSignature');
            if (keyUsageExt.nonRepudiation) keyUsage.push('nonRepudiation');
            if (keyUsageExt.keyEncipherment) keyUsage.push('keyEncipherment');
          }

          const subjectCN = cert.subject.getField('CN')?.value ?? '';
          const issuerCN  = cert.issuer.getField('CN')?.value ?? '';
          const serial    = cert.serialNumber;
          const validFrom = cert.validity.notBefore.toISOString();
          const validTo   = cert.validity.notAfter.toISOString();

          // Build DER base64
          const derB64 = Buffer.from(
            forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes(),
            'binary',
          ).toString('base64');

          // Thumbprint = SHA-256 of DER
          const sha = forge.md.sha256.create();
          sha.update(forge.util.createBuffer(x509Buf).bytes());
          const thumbprint = sha.digest().toHex();

          results.push({
            thumbprint,
            subjectCN,
            issuerCN,
            serialNumber: serial,
            validFrom,
            validTo,
            keyUsage,
            derB64,
            slotIndex: slot.index ?? 0,
          });
        } catch {
          // Malformed cert — skip
        }
      }
      session.close();
    } catch {
      try { session?.close(); } catch {}
    }
  }

  return results;
}

/**
 * Sign a raw hash (SHA-256 digest) using the private key on the token.
 * Prompts the user for their PIN via the PKCS#11 C_Login call.
 *
 * @param {import('graphene-pk11').Module} lib
 * @param {string} thumbprint  — hex SHA-256 of the cert DER
 * @param {Buffer} hashBuf     — raw 32-byte SHA-256 digest
 * @param {string} pin         — token PIN (from the helper UI prompt)
 * @returns {Buffer}           — raw RSA/ECDSA signature bytes
 */
function signHash(lib, thumbprint, hashBuf, pin) {
  for (const slot of lib.getSlots(true)) {
    let session;
    try {
      // R/W session for C_Login
      session = slot.open(SessionFlag.RW_SESSION | SessionFlag.SERIAL_SESSION);
      session.login(pin);

      // Find the matching certificate first, then locate the private key by CKA_ID
      const certs = session.find({ class: ObjectClass.CERTIFICATE });
      let certId = null;

      for (const certObj of certs) {
        const x509Buf = Buffer.from(certObj.getAttribute({ value: null, id: null }).value);
        const cert = forge.pki.certificateFromDer(forge.util.createBuffer(x509Buf));

        const sha = forge.md.sha256.create();
        sha.update(forge.util.createBuffer(x509Buf).bytes());
        const tp = sha.digest().toHex();

        if (tp === thumbprint) {
          certId = certObj.getAttribute({ id: null }).id;
          break;
        }
      }

      if (!certId) {
        session.logout();
        session.close();
        continue; // not on this slot
      }

      // Find the private key with same CKA_ID
      const keys = session.find({
        class: ObjectClass.PRIVATE_KEY,
        id: certId,
      });

      if (keys.length === 0) {
        session.logout();
        session.close();
        continue;
      }

      const privKey = keys.items(0);
      const keyType = privKey.getAttribute({ keyType: null }).keyType;

      let mechanism;
      if (keyType === KeyType.RSA) {
        // RSA PKCS#1 v1.5 with SHA-256 DigestInfo wrapping
        mechanism = { name: 'SHA256_RSA_PKCS', params: null };
      } else if (keyType === KeyType.EC) {
        mechanism = { name: 'ECDSA_SHA256', params: null };
      } else {
        throw new Error(`Unsupported key type: ${keyType}`);
      }

      // For RSA_PKCS we must sign the full DigestInfo, not raw hash
      // For SHA256_RSA_PKCS the PKCS#11 lib does the wrapping internally
      const sign = session.createSign(mechanism, privKey);
      sign.once(hashBuf);
      const sig = sign.final();

      session.logout();
      session.close();
      return Buffer.from(sig);
    } catch (err) {
      try { session?.logout(); } catch {}
      try { session?.close(); } catch {}
      throw err;
    }
  }

  throw new Error('Certificate not found on any token slot');
}

module.exports = { listCertificates, signHash };
