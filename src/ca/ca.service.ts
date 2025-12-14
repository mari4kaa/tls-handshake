import { Injectable, Global } from '@nestjs/common';
import { CryptoService } from '../crypto/crypto.service';
import { Certificate } from '../types';

let globalCAInstance: CertificateAuthorityService | null = null;

@Global()
@Injectable()
export class CertificateAuthorityService {
  private rootCertificate: Certificate;
  private rootPrivateKey: string;
  private issuedCertificates: Map<string, string> = new Map();
  private static instanceCount = 0;

  constructor(private cryptoService: CryptoService) {
    if (!globalCAInstance) {
      this.initializeRootCA();
      globalCAInstance = this;
      CertificateAuthorityService.instanceCount = 1;
    } else {
      this.rootCertificate = globalCAInstance.rootCertificate;
      this.rootPrivateKey = globalCAInstance.rootPrivateKey;
      this.issuedCertificates = globalCAInstance.issuedCertificates;
      CertificateAuthorityService.instanceCount++;
      console.log(`Reusing existing Root CA (instance ${CertificateAuthorityService.instanceCount})`);
      return;
    }
  }

  getSharedCAKeys(): { publicKey: string; privateKey: string; subject: string } {
    return {
      publicKey: this.rootCertificate.publicKey,
      privateKey: this.rootPrivateKey,
      subject: this.rootCertificate.subject || 'CN=Root CA,O=TLS Simulation',
    };
  }

  loadSharedCA(publicKey: string, privateKey: string, subject: string): void {
    if (globalCAInstance && globalCAInstance !== this) {
      throw new Error('Cannot load shared CA - CA already initialized');
    }

    this.rootPrivateKey = privateKey;
    
    const certJson = this.cryptoService.createSelfSignedCertificate(
      publicKey,
      privateKey,
      subject
    );

    this.rootCertificate = {
      publicKey,
      privateKey,
      pemCertificate: certJson,
      issuedBy: 'Self',
      subject,
      validFrom: new Date(),
      validTo: new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000),
    };

    console.log('Shared Root CA loaded');
  }

  private initializeRootCA(): void {
    const { publicKey, privateKey } = this.cryptoService.generateRSAKeyPair();
    this.rootPrivateKey = privateKey;

    const certJson = this.cryptoService.createSelfSignedCertificate(
      publicKey,
      privateKey,
      'CN=Root CA,O=TLS Simulation'
    );

    this.rootCertificate = {
      publicKey,
      privateKey,
      pemCertificate: certJson,
      issuedBy: 'Self',
      subject: 'CN=Root CA,O=TLS Simulation',
      validFrom: new Date(),
      validTo: new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000), // 10 years
    };

    console.log('Root CA initialized');
  }

  getRootCertificate(): Certificate {
    return {
      publicKey: this.rootCertificate.publicKey,
      pemCertificate: this.rootCertificate.pemCertificate,
      subject: this.rootCertificate.subject,
      validFrom: this.rootCertificate.validFrom,
      validTo: this.rootCertificate.validTo,
    };
  }

  signServerCertificate(
    publicKey: string,
    subject: string
  ): string {
    const cert = {
      version: 3,
      serialNumber: this.cryptoService.generateRandomBytes(16).toString('hex'),
      subject,
      issuer: this.rootCertificate.subject,
      publicKey,
      validFrom: new Date(),
      validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
      signature: this.cryptoService.signData(
        Buffer.from(publicKey + subject),
        this.rootPrivateKey
      ),
    };

    const certJson = JSON.stringify(cert);
    this.issuedCertificates.set(subject, certJson);
    
    return certJson;
  }

  verifyCertificate(certJson: string): boolean {
    const cert = this.cryptoService.parseCertificate(certJson);
    if (!cert) return false;

    const dataToVerify = Buffer.from(cert.publicKey + cert.subject);
    return this.cryptoService.verifySignature(
      dataToVerify,
      cert.signature,
      this.rootCertificate.publicKey
    );
  }

  getIssuedCertificates(): string[] {
    return Array.from(this.issuedCertificates.values());
  }
}
