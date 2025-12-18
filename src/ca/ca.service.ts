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
    console.log('\n=== CERTIFICATE AUTHORITY: Signing Server Certificate ===');
    console.log('Certificate Request:');
    console.log(`  - Subject: ${subject}`);
    console.log(`  - Public Key length: ${publicKey.length} characters`);
    console.log(`  - Public Key: ${publicKey}`);
    
    const serialNumber = this.cryptoService.generateRandomBytes(16).toString('hex');
    const validFrom = new Date();
    const validTo = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    
    console.log('\nCertificate Generation:');
    console.log(`  - Serial Number: ${serialNumber}`);
    console.log(`  - Issuer: ${this.rootCertificate.subject}`);
    console.log(`  - Valid From: ${validFrom.toISOString()}`);
    console.log(`  - Valid To: ${validTo.toISOString()}`);
    console.log(`  - Validity Period: 1 year (365 days)`);
    
    const dataToSign = Buffer.from(publicKey + subject);
    console.log('\nSigning Certificate:');
    console.log(`  - Data length: ${dataToSign.length} bytes`);
    console.log(`  - Signing with CA Private Key`);
    console.log(`  - Signature Algorithm: SHA-256 with RSA`);
    
    const signature = this.cryptoService.signData(
      dataToSign,
      this.rootPrivateKey
    );
    
    console.log(`  - Signature generated: ${signature}`);
    console.log(`  - Signature length: ${signature.length} characters`);

    const cert = {
      version: 3,
      serialNumber,
      subject,
      issuer: this.rootCertificate.subject,
      publicKey,
      validFrom,
      validTo, // 1 year
      signature,
    };

    const certJson = JSON.stringify(cert);
    this.issuedCertificates.set(subject, certJson);

    console.log('\nCertificate Signed Successfully:');
    console.log(`  - Total certificates issued: ${this.issuedCertificates.size}`);
    console.log(`  - Certificate JSON length: ${certJson.length} characters`);
    console.log(`  - Certificate: ${certJson}`);
    
    return certJson;
  }

  verifyCertificate(certJson: string): boolean {
    console.log('\n=== HANDSHAKE STEP 3: Certificate Verification with CA ===');
    console.log('Certificate Verification Request:');
    console.log(`  - Certificate JSON length: ${certJson.length} characters`);
    console.log(`  - Certificate: ${certJson}`);

    const cert = this.cryptoService.parseCertificate(certJson);
    if (!cert) {
        console.log('Verification Result: FAILED ✗');
        console.log('  - Reason: Certificate parsing failed');
        return false;
      }
  
      console.log('\nParsed Certificate:');
      console.log(`  - Version: ${cert.version}`);
      console.log(`  - Serial Number: ${cert.serialNumber}`);
      console.log(`  - Subject: ${cert.subject}`);
      console.log(`  - Issuer: ${cert.issuer}`);
      console.log(`  - Valid From: ${cert.validFrom}`);
      console.log(`  - Valid To: ${cert.validTo}`);
      console.log(`  - Public Key: ${cert.publicKey}`);
      console.log(`  - Signature: ${cert.signature}`);
  
      // Verify signature with root CA public key
      console.log('\nSignature Verification:');
      console.log(`  - Data to verify: Public Key + Subject`);
      const dataToVerify = Buffer.from(cert.publicKey + cert.subject);
      console.log(`  - Data length: ${dataToVerify.length} bytes`);
      console.log(`  - Verifying with CA Public Key`);
      console.log(`  - CA Public Key (first 100 chars): ${this.rootCertificate.publicKey.substring(0, 100)}...`);
      console.log(`  - Algorithm: SHA-256 with RSA signature verification`);
      
      const isValid = this.cryptoService.verifySignature(
        dataToVerify,
        cert.signature,
        this.rootCertificate.publicKey
      );
      
      console.log('\nVerification Result:', isValid ? 'SUCCESS ✓' : 'FAILED ✗');
      if (isValid) {
        console.log('  - Certificate signature is valid');
        console.log('  - Certificate was issued by trusted CA');
        console.log('  - Certificate authenticity confirmed');
      } else {
        console.log('  - Certificate signature is invalid');
        console.log('  - Certificate may be forged or corrupted');
        console.log('  - Certificate NOT trusted');
      }
      
      return isValid;
  }

  getIssuedCertificates(): string[] {
    return Array.from(this.issuedCertificates.values());
  }
}
