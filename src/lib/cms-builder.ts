/**
 * Builds a PAdES-compliant CMS SignedData structure (ETSI EN 319 122 / RFC 5652).
 *
 * Flow:
 *   1. Caller provides SHA-256 of the PDF byte-range (byteRangeDigest).
 *   2. We build the signedAttributes SET and return its DER for the helper to sign.
 *   3. After the helper returns the raw RSA/ECDSA signature we assemble the full
 *      CMS and hex-encode it for insertion into /Contents.
 */

import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import { fromBER } from 'asn1js';
import { Crypto as PecularCrypto } from '@peculiar/webcrypto';

// pkijs needs a WebCrypto engine — use the Node polyfill
const webcrypto = new PecularCrypto();
const engine = new pkijs.CryptoEngine({ name: 'node', crypto: webcrypto as unknown as Crypto });
pkijs.setEngine('node', engine);

// OIDs
const OID_CONTENT_TYPE   = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_SIGNING_TIME   = '1.2.840.113549.1.9.5';
const OID_ESS_CERT_V2    = '1.2.840.113549.1.9.16.2.47'; // ESS signing-certificate-v2
const OID_DATA           = '1.2.840.113549.1.2.1';        // id-data
const OID_SHA256         = '2.16.840.1.101.3.4.2.1';
const OID_RSA            = '1.2.840.113549.1.1.1';

/** Extract a plain ArrayBuffer from a Buffer (avoids SharedArrayBuffer type errors). */
function toAB(buf: Buffer): ArrayBuffer {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

function parseCert(derB64: string): pkijs.Certificate {
  const der = Buffer.from(derB64, 'base64');
  const asn = fromBER(toAB(der));
  if (asn.offset === -1) throw new Error('Failed to parse certificate DER');
  return new pkijs.Certificate({ schema: asn.result });
}

/** Compute SHA-256 of DER-encoded certificate for ESS signing-certificate-v2. */
async function certSha256(certDerB64: string): Promise<ArrayBuffer> {
  const der = Buffer.from(certDerB64, 'base64');
  return webcrypto.subtle.digest('SHA-256', toAB(der));
}

/** Build an ESS SigningCertificateV2 attribute value for the signer cert. */
async function buildEssCertV2(certDerB64: string): Promise<asn1js.Sequence> {
  const hash = await certSha256(certDerB64);
  // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, certHash OCTET STRING }
  return new asn1js.Sequence({
    value: [
      new asn1js.Sequence({
        // certs SEQUENCE OF ESSCertIDv2
        value: [
          new asn1js.Sequence({
            value: [
              // hashAlgorithm (SHA-256, default if omitted but explicit is safer)
              new asn1js.Sequence({
                value: [new asn1js.ObjectIdentifier({ value: OID_SHA256 })],
              }),
              // certHash
              new asn1js.OctetString({ valueHex: hash }),
            ],
          }),
        ],
      }),
    ],
  });
}

export interface SignedAttrsResult {
  /** DER of the signedAttributes SET (with SET tag, for signing) */
  signedAttrsDer: Buffer;
  /** SHA-256 of signedAttrsDer — the actual digest the token must sign */
  tbsDigest: Buffer;
}

/**
 * Build PAdES signed attributes and return the DER and its SHA-256.
 * The helper will sign tbsDigest with RSA-PKCS1-v1.5.
 */
export async function buildSignedAttrs(
  byteRangeDigest: Buffer,
  certDerB64: string,
  signingTime: Date,
): Promise<SignedAttrsResult> {
  const essCertV2 = await buildEssCertV2(certDerB64);

  // Build as a SET of Attributes (IMPLICIT [0] re-tagged to SET for signing per RFC 5652 §5.4)
  const attrs = new asn1js.Set({
    value: [
      // contentType
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: OID_CONTENT_TYPE }),
          new asn1js.Set({ value: [new asn1js.ObjectIdentifier({ value: OID_DATA })] }),
        ],
      }),
      // signingTime
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: OID_SIGNING_TIME }),
          new asn1js.Set({
            value: [
              new asn1js.UTCTime({ valueDate: signingTime }),
            ],
          }),
        ],
      }),
      // messageDigest
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: OID_MESSAGE_DIGEST }),
          new asn1js.Set({
            value: [new asn1js.OctetString({ valueHex: toAB(byteRangeDigest) })],
          }),
        ],
      }),
      // ESS signing-certificate-v2 (PAdES B-B requirement)
      new asn1js.Sequence({
        value: [
          new asn1js.ObjectIdentifier({ value: OID_ESS_CERT_V2 }),
          new asn1js.Set({ value: [essCertV2] }),
        ],
      }),
    ],
  });

  const signedAttrsDer = Buffer.from(attrs.toBER(false));
  const digestAb = await webcrypto.subtle.digest('SHA-256', toAB(signedAttrsDer));
  const tbsDigest = Buffer.from(digestAb);

  return { signedAttrsDer, tbsDigest };
}

export interface BuildCmsOptions {
  signedAttrsDer: Buffer;
  signatureValue: Buffer;  // raw RSA/ECDSA bytes from token
  certDerB64: string;      // signer cert DER, base64
  chainB64?: string[];     // intermediate + root DER, base64, inner→outer
}

/**
 * Assemble the complete CMS SignedData DER blob ready to hex-encode into /Contents.
 */
export function buildCms(opts: BuildCmsOptions): Buffer {
  const { signedAttrsDer, signatureValue, certDerB64, chainB64 = [] } = opts;

  // Parse signer cert
  const signerCertDer = Buffer.from(certDerB64, 'base64');
  const signerCertAsn = fromBER(toAB(signerCertDer));
  const signerCert = new pkijs.Certificate({ schema: signerCertAsn.result });

  // Collect all certs (signer + chain)
  const allCertDers = [certDerB64, ...chainB64];
  const certObjects = allCertDers.map(b64 => {
    const der = Buffer.from(b64, 'base64');
    const asn = fromBER(toAB(der));
    return new pkijs.Certificate({ schema: asn.result });
  });

  // Build SignerInfo
  const signerInfo = new pkijs.SignerInfo({
    version: 1,
    sid: new pkijs.IssuerAndSerialNumber({
      issuer: signerCert.issuer,
      serialNumber: signerCert.serialNumber,
    }),
    digestAlgorithm: new pkijs.AlgorithmIdentifier({
      algorithmId: OID_SHA256,
    }),
    signedAttrs: new pkijs.SignedAndUnsignedAttributes({
      type: 0, // signedAttributes
      attributes: [],
    }),
    signatureAlgorithm: new pkijs.AlgorithmIdentifier({
      algorithmId: OID_RSA,
    }),
    signature: new asn1js.OctetString({ valueHex: toAB(signatureValue) }),
  });

  // Attach the pre-built signedAttrs DER directly
  // We re-parse so pkijs can use them properly
  const saAsn = fromBER(toAB(signedAttrsDer));
  signerInfo.signedAttrs = new pkijs.SignedAndUnsignedAttributes({
    type: 0,
    encodedValue: saAsn.result.valueBeforeDecode,
  });

  // Build SignedData
  const signedData = new pkijs.SignedData({
    version: 1,
    digestAlgorithms: [
      new pkijs.AlgorithmIdentifier({ algorithmId: OID_SHA256 }),
    ],
    encapContentInfo: new pkijs.EncapsulatedContentInfo({
      eContentType: OID_DATA,
      // detached — no eContent
    }),
    certificates: certObjects,
    signerInfos: [signerInfo],
  });

  const contentInfo = new pkijs.ContentInfo({
    contentType: pkijs.ContentInfo.SIGNED_DATA,
    content: signedData.toSchema(true),
  });

  return Buffer.from(contentInfo.toSchema().toBER(false));
}
