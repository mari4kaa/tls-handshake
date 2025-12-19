import { Injectable, Logger, Inject } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { 
  generateKeyPairSync, 
  createVerify,
} from 'crypto';
import { firstValueFrom } from 'rxjs';

export interface CaConfig {
  authorityUrl: string;
  retryAttempts: number;
  retryDelay: number;
  certificateValidityDays: number;
}

export interface Certificate {
  version: number;
  serialNumber: string;
  subject: string;
  issuer: string;
  publicKey:  string;
  validFrom: string;
  validTo: string;
  signature?: string;
  issuedTo?: string;
}

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

@Injectable()
export class CaClientService {
  private caPublicKey: string;
  private myCertificate: Certificate;
  private myPublicKey: string;
  private myPrivateKey: string;
  
  constructor(
    @Inject('NODE_ID') private readonly nodeId: string,
    @Inject('CA_CONFIG') private readonly config: CaConfig,
    private readonly logger: Logger,
    private readonly httpService: HttpService,
  ) {}

  async initialize(): Promise<void> {
    this.logger.log('═══════════════════════════════════════════════════════════');
    this.logger.log('  CA CLIENT INITIALIZATION');
    this.logger.log('═══════════════════════════════════════════════════════════');
    this.logger.log(`  Node: ${this.nodeId}`);
    this.logger.log(`  Role: CLIENT (verification only)`);
    this.logger.log(`  CA Authority:  ${this.config.authorityUrl}`);
    this.logger.log('');
    
    // Завантаження публічного ключа CA
    await this.fetchCAPublicKey();
    
    // Запит сертифікату для себе
    await this.requestCertificate();
    
    this.logger.log('✓ CA client initialized successfully');
    this.logger.log('═══════════════════════════════════════════════════════════');
    this.logger.log('');
  }

  private async fetchCAPublicKey(): Promise<void> {
    this.logger.log('Fetching CA public key from authority...');
    
    let attempts = 0;
    const maxAttempts = this.config.retryAttempts;
    
    while (attempts < maxAttempts) {
      try {
        const response = await firstValueFrom(
          this.httpService.get(`${this.config.authorityUrl}/public-key`, {
            timeout: 3000,
          })
        );
        
        this.caPublicKey = response.data.publicKey;
        
        this.logger.log('✓ CA public key retrieved');
        this.logger.log(`  Key length: ${this.caPublicKey.length} characters`);
        this.logger.log(`  Issuer: ${response.data.issuer}`);
        this.logger.log(`  Algorithm: ${response.data.algorithm}`);
        this.logger.log('');
        
        return;
        
      } catch (error) {
        attempts++;
        this. logger.warn(
          `Failed to fetch CA public key (attempt ${attempts}/${maxAttempts}): ${error.message}`
        );
        
        if (attempts >= maxAttempts) {
          throw new Error(
            'Cannot initialize:  CA authority unavailable after maximum retry attempts'
          );
        }
        
        // Exponential backoff
        const delay = this.config.retryDelay * Math.pow(2, attempts - 1);
        this.logger.log(`Retrying in ${delay}ms... `);
        await this.sleep(delay);
      }
    }
  }

  private async requestCertificate(): Promise<void> {
    this.logger.log('═══════════════════════════════════════════════════════════');
    this.logger.log('  REQUESTING CERTIFICATE FROM CA');
    this.logger.log('═══════════════════════════════════════════════════════════');
    
    // Генерація власної пари ключів
    this.logger.log('Generating RSA-2048 key pair...');
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    
    this.logger.log('✓ Key pair generated');
    this.logger.log(`  Public Key:  ${publicKey.length} characters`);
    this.logger.log(`  Private Key: ${privateKey.length} characters (secured)`);
    this.logger.log('');
    
    // Створення CSR
    const csr: CertificateSigningRequest = {
      nodeId: this.nodeId,
      subject: `CN=${this.nodeId},O=TLS Node`,
      publicKey: publicKey,
      requestedAt: new Date().toISOString(),
      metadata: {
        purpose: 'TLS Server/Client Certificate',
      },
    };
    
    this.logger.log('Certificate Signing Request created: ');
    this.logger.log(`  Node ID: ${csr.nodeId}`);
    this.logger.log(`  Subject: ${csr.subject}`);
    this.logger.log(`  Public Key length: ${publicKey.length} characters`);
    this.logger.log('');
    
    // Відправка CSR до CA
    let attempts = 0;
    const maxAttempts = this.config. retryAttempts;
    
    while (attempts < maxAttempts) {
      try {
        this.logger.log(`Sending CSR to CA authority...  (attempt ${attempts + 1}/${maxAttempts})`);
        
        const response = await firstValueFrom(
          this. httpService.post(
            `${this.config.authorityUrl}/sign-certificate`,
            csr,
            { timeout: 5000 }
          )
        );
        
        this.myCertificate = response.data;
        
        this.logger.log('');
        this.logger.log('✓ Certificate received and signed by CA');
        this.logger. log(`  Serial Number: ${this.myCertificate.serialNumber}`);
        this.logger.log(`  Subject: ${this.myCertificate.subject}`);
        this.logger.log(`  Issuer: ${this.myCertificate.issuer}`);
        this.logger.log(`  Valid From: ${this.myCertificate.validFrom}`);
        this.logger.log(`  Valid To: ${this.myCertificate.validTo}`);
        this.logger.log(`  Signature length: ${this.myCertificate.signature.length} characters`);
        this.logger.log('');
        
        // Збереження приватного ключа
        this.myPrivateKey = privateKey;
        this.myPublicKey = publicKey;
        
        this.logger.log('✓ Certificate and keys stored securely');
        this.logger.log('═══════════════════════════════════════════════════════════');
        this.logger.log('');
        
        return;
        
      } catch (error) {
        attempts++;
        this.logger. error(
          `Failed to get certificate signed (attempt ${attempts}/${maxAttempts}): ${error.message}`
        );
        
        if (attempts >= maxAttempts) {
          throw new Error(
            'Cannot obtain certificate: CA authority unavailable or rejected CSR'
          );
        }
        
        const delay = this.config.retryDelay * Math.pow(2, attempts - 1);
        this.logger.log(`Retrying in ${delay}ms...`);
        await this.sleep(delay);
      }
    }
  }

  // Верифікація сертифікату (доступна всім)
  async verifyCertificate(certificate:  Certificate): Promise<boolean> {
    this.logger. log('');
    this.logger.log('=== VERIFYING CERTIFICATE ===');
    this.logger.log(`Serial:  ${certificate.serialNumber}`);
    this.logger.log(`Subject: ${certificate.subject}`);
    
    // Перевірка терміну дії
    const now = new Date();
    const validFrom = new Date(certificate.validFrom);
    const validTo = new Date(certificate.validTo);
    
    if (now < validFrom) {
      this.logger.warn('✗ Certificate not yet valid');
      return false;
    }
    
    if (now > validTo) {
      this.logger.warn('✗ Certificate expired');
      return false;
    }
    
    // Перевірка підпису
    const dataToVerify = certificate.publicKey + certificate.subject;
    const verify = createVerify('RSA-SHA256');
    verify.update(dataToVerify);
    verify.end();
    
    const isValid = verify.verify(
      this.caPublicKey,
      Buffer. from(certificate.signature, 'base64')
    );
    
    if (isValid) {
      this.logger.log('✓ Certificate signature valid');
      this.logger.log(`  Verified using CA public key`);
    } else {
      this.logger.warn('✗ Certificate signature invalid');
    }
    
    this.logger.log('');
    
    return isValid;
  }

  getCAPublicKey(): string {
    return this.caPublicKey;
  }

  getMyCertificate(): Certificate {
    return this.myCertificate;
  }

  getMyPublicKey(): string {
    return this.myPublicKey;
  }

  getMyPrivateKey(): string {
    return this.myPrivateKey;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}