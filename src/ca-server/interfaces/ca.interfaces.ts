export interface CertificateSigningRequest {
  nodeId: string;
  subject: string;
  publicKey: string;
  requestedAt: string;
  metadata?: {
    ipAddress?: string;
    purpose?: string;
  };
}

export interface Certificate {
  version: number;
  serialNumber: string;
  subject: string;
  issuer: string;
  publicKey: string;
  validFrom: string;
  validTo: string;
  signature?: string;
  issuedTo?: string;
}

export interface CertificateVerificationResult {
  valid: boolean;
  reason?: string;
  certificate?: Certificate;
}
