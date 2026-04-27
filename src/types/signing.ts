export interface PrepareRequest {
  pdfBase64: string;
  reason: string;
  location: string;
  signerName: string;
  contactInfo?: string;
  signatureRect?: [number, number, number, number]; // [x1, y1, x2, y2]
  pageNumber?: number;
}

export interface PrepareResponse {
  pdfId: string;
  digestB64: string;
  hashAlgo: 'SHA-256';
}

export interface FinalizeRequest {
  pdfId: string;
  /** Raw RSA/ECDSA signature over SHA-256(signedAttrs DER) from the token */
  signatureB64: string;
  /** DER-encoded end-entity certificate from the token */
  certificateB64: string;
  /** DER-encoded intermediate + root chain (optional but recommended) */
  chainB64?: string[];
}

export interface FinalizeResponse {
  signedPdfB64: string;
}

export interface TimestampRequest {
  pdfId: string;
}

export interface DscCertificate {
  thumbprint: string;
  subjectCN: string;
  issuerCN: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  keyUsage: string[];
  derB64: string;
  chainB64?: string[];
}

export interface HelperInfo {
  vendor: string;
  baseUrl: string;
  version?: string;
}

export type SigningStatus =
  | 'idle'
  | 'detecting'
  | 'enumerating'
  | 'preparing'
  | 'signing'
  | 'embedding'
  | 'timestamping'
  | 'done'
  | 'error';

export interface SigningError {
  code:
    | 'helper_not_found'
    | 'no_certificates'
    | 'user_cancel'
    | 'pin_blocked'
    | 'token_removed'
    | 'technical_error';
  message: string;
}
