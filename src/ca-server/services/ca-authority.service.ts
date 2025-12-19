import { Injectable, Logger, BadRequestException, NotFoundException } from '@nestjs/common';
import { 
  generateKeyPairSync, 
  createSign, 
  createVerify,
  randomBytes 
} from 'crypto';
import { Certificate, CertificateSigningRequest, CertificateVerificationResult } from '../interfaces/ca.interfaces';

@Injectable()
export class CaAuthorityService {
  private caPublicKey: string;
  private caPrivateKey: string;
  private issuedCertificates: Map<string, Certificate> = new Map();
  private revokedSerialNumbers: Set<string> = new Set();
  
  constructor(private readonly logger: Logger) {
    this.initializeRootCA();
  }

  private initializeRootCA(): void {
    this.logger.log('═══════════════════════════════════════════════════════════');
    this.logger.log('  INITIALIZING ROOT CERTIFICATE AUTHORITY');
    this.logger.log('═══════════════════════════════════════════════════════════');
    
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    
    this.caPublicKey = publicKey;
    this.caPrivateKey = privateKey;
    
    this.logger.log('');
    this.logger.log('✓ Root CA Keys Generated');
    this.logger.log(`  Algorithm: RSA-2048`);
    this.logger.log(`  Public Key: ${publicKey. length} characters`);
    this.logger.log(`  Private Key: ${privateKey.length} characters (SECURED IN MEMORY)`);
    this.logger.log('');
    this.logger.log('✓ Root Certificate Authority Ready');
    this.logger.log('  Can issue certificates to network nodes');
    this.logger.log('  Can verify certificate signatures');
    this.logger.log('  Can revoke compromised certificates');
    this.logger.log('═══════════════════════════════════════════════════════════');
    this.logger.log('');
  }

  async signCertificate(csr: CertificateSigningRequest): Promise<Certificate> {
    this.logger.log('');
    this.logger.log('┌─────────────────────────────────────────────────────────┐');
    this.logger.log('│           CERTIFICATE SIGNING REQUEST                  │');
    this.logger.log('└─────────────────────────────────────────────────────────┘');
    this.logger.log(`  Requester: ${csr.nodeId}`);
    this.logger.log(`  Subject: ${csr.subject}`);
    this.logger.log(`  Public Key: ${csr.publicKey. substring(0, 50)}...`);
    this.logger.log(`  Requested At: ${csr.requestedAt}`);
    
    // Валідація CSR
    this.validateCSR(csr);
    
    // Генерація серійного номера
    const serialNumber = randomBytes(16).toString('hex');
    
    const now = new Date();
    const validTo = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
    
    const certificate: Certificate = {
      version: 3,
      serialNumber,
      subject: csr.subject,
      issuer: 'CN=Root CA,O=TLS Simulation',
      publicKey: csr.publicKey,
      validFrom: now.toISOString(),
      validTo: validTo. toISOString(),
      issuedTo: csr.nodeId,
    };
    
    // Підписання
    const dataToSign = certificate.publicKey + certificate.subject;
    const sign = createSign('RSA-SHA256');
    sign.update(dataToSign);
    sign.end();
    
    certificate.signature = sign.sign(this.caPrivateKey, 'base64');
    
    // Збереження
    this.issuedCertificates.set(serialNumber, {
      ...certificate,
      issuedAt: now,
    } as any);
    
    this.logger.log('');
    this.logger.log('✓ Certificate Signed Successfully');
    this.logger.log(`  Serial Number: ${serialNumber}`);
    this.logger.log(`  Issued To: ${csr.nodeId}`);
    this.logger.log(`  Valid From: ${now.toISOString()}`);
    this.logger.log(`  Valid Until: ${validTo.toISOString()}`);
    this.logger.log(`  Signature Length: ${certificate.signature.length} chars`);
    this.logger.log(`  Total Certificates Issued: ${this.issuedCertificates.size}`);
    this.logger.log('─────────────────────────────────────────────────────────');
    this.logger.log('');
    
    return certificate;
  }

  private validateCSR(csr: CertificateSigningRequest): void {
    if (!csr. nodeId || !csr.subject || !csr.publicKey) {
      throw new BadRequestException('Invalid CSR: missing required fields');
    }
    
    if (! csr.publicKey. includes('BEGIN PUBLIC KEY')) {
      throw new BadRequestException('Invalid public key format');
    }
    
    // Перевірка чи вузол вже має валідний сертифікат
    const existingCert = Array.from(this.issuedCertificates.values())
      .find(cert => cert. issuedTo === csr.nodeId);
    
    if (existingCert && !this.isCertificateExpired(existingCert)) {
      this.logger.warn(`⚠ Node ${csr.nodeId} already has valid certificate (serial: ${existingCert.serialNumber})`);
      this.logger.warn(`  Issuing new certificate anyway... `);
    }
  }

  verifyCertificate(certificate:  Certificate): CertificateVerificationResult {
    this.logger. log('');
    this.logger.log('┌─────────────────────────────────────────────────────────┐');
    this.logger.log('│           CERTIFICATE VERIFICATION                     │');
    this.logger.log('└─────────────────────────────────────────────────────────┘');
    this.logger.log(`  Serial Number: ${certificate.serialNumber}`);
    this.logger.log(`  Subject: ${certificate.subject}`);
    
    // Перевірка терміну дії
    const now = new Date();
    const validFrom = new Date(certificate.validFrom);
    const validTo = new Date(certificate.validTo);
    
    if (now < validFrom) {
      this.logger.warn('✗ Certificate is not yet valid');
      return {
        valid: false,
        reason: 'Certificate not yet valid',
      };
    }
    
    if (now > validTo) {
      this.logger.warn('✗ Certificate has expired');
      return {
        valid: false,
        reason:  'Certificate expired',
      };
    }
    
    // Перевірка чи не відкликаний
    if (this.revokedSerialNumbers.has(certificate.serialNumber)) {
      this.logger.warn('✗ Certificate has been revoked');
      return {
        valid: false,
        reason: 'Certificate revoked',
      };
    }
    
    // Перевірка підпису
    const dataToVerify = certificate.publicKey + certificate.subject;
    const verify = createVerify('RSA-SHA256');
    verify.update(dataToVerify);
    verify.end();
    
    const isSignatureValid = verify.verify(
      this.caPublicKey,
      Buffer.from(certificate.signature, 'base64')
    );
    
    if (!isSignatureValid) {
      this.logger.warn('✗ Certificate signature is invalid');
      return {
        valid: false,
        reason:  'Invalid signature',
      };
    }
    
    this.logger.log('✓ Certificate is VALID');
    this.logger.log(`  Issued To: ${certificate.issuedTo}`);
    this.logger.log(`  Valid Until: ${certificate.validTo}`);
    this.logger.log('─────────────────────────────────────────────────────────');
    this.logger.log('');
    
    return {
      valid:  true,
      certificate,
    };
  }

  private isCertificateExpired(cert: Certificate): boolean {
    return new Date() > new Date(cert.validTo);
  }

  getPublicKey(): string {
    return this.caPublicKey;
  }

  getIssuedCertificates(): Certificate[] {
    return Array.from(this.issuedCertificates.values());
  }

  revokeCertificate(serialNumber: string, reason:  string): void {
    this.logger.log('');
    this.logger.log(`⚠ REVOKING CERTIFICATE`);
    this.logger.log(`  Serial Number: ${serialNumber}`);
    this.logger.log(`  Reason: ${reason}`);
    
    if (! this.issuedCertificates.has(serialNumber)) {
      throw new NotFoundException('Certificate not found in registry');
    }
    
    this.revokedSerialNumbers.add(serialNumber);
    
    this.logger.log(`✓ Certificate revoked successfully`);
    this.logger.log(`  Total revoked certificates: ${this.revokedSerialNumbers.size}`);
    this.logger.log('');
  }

  isRevoked(serialNumber: string): boolean {
    return this.revokedSerialNumbers.has(serialNumber);
  }

  getCertificateBySerial(serialNumber: string): Certificate | undefined {
    return this.issuedCertificates.get(serialNumber);
  }
}