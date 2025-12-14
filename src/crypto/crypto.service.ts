import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

@Injectable()
export class CryptoService {

  generateRSAKeyPair(): { publicKey: string; privateKey: string } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });

    return { publicKey, privateKey };
  }

  rsaEncrypt(data: Buffer, publicKey: string): Buffer {
    return crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      data
    );
  }

  rsaDecrypt(encryptedData: Buffer, privateKey: string): Buffer {
    return crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encryptedData
    );
  }

  generateRandomBytes(length: number): Buffer {
    return crypto.randomBytes(length);
  }


  deriveSessionKeys(
    premasterSecret: Buffer,
    clientRandom: Buffer,
    serverRandom: Buffer
  ): { encryptionKey: Buffer; ivSeed: Buffer; hmacKey: Buffer } {
    const salt = Buffer.concat([clientRandom, serverRandom]);
    const info = Buffer.from('TLS session');

    // derive 80 bytes: 32 for encryption, 16 for IV seed, 32 for HMAC
    const derivedKey = crypto.hkdfSync(
      'sha256',
      premasterSecret,
      salt,
      info,
      80
    );

    return {
      encryptionKey: Buffer.from(derivedKey.slice(0, 32)), // AES-256 key
      ivSeed: Buffer.from(derivedKey.slice(32, 48)), // 16 bytes for IV seed
      hmacKey: Buffer.from(derivedKey.slice(48, 80)), // 32 bytes for HMAC
    };
  }

  // using AES-256-GCM
  aesEncrypt(
    plaintext: Buffer,
    key: Buffer,
    iv: Buffer
  ): { ciphertext: Buffer; authTag: Buffer } {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return { ciphertext, authTag };
  }

  aesDecrypt(
    ciphertext: Buffer,
    key: Buffer,
    iv: Buffer,
    authTag: Buffer
  ): Buffer {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  generateIV(ivSeed: Buffer, sequenceNumber: number): Buffer {
    const seqBuffer = Buffer.alloc(16);
    seqBuffer.writeUInt32BE(sequenceNumber, 12);
    
    const iv = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) {
      iv[i] = ivSeed[i] ^ seqBuffer[i];
    }
    
    return iv;
  }

  createSelfSignedCertificate(
    publicKey: string,
    privateKey: string,
    subject: string
  ): string {
    const cert = {
      version: 3,
      serialNumber: crypto.randomBytes(16).toString('hex'),
      subject,
      issuer: subject, // self-signed
      publicKey,
      validFrom: new Date(),
      validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
      signature: this.signData(Buffer.from(publicKey + subject), privateKey),
    };

    return JSON.stringify(cert);
  }

  // sign data with private key
  signData(data: Buffer, privateKey: string): string {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, 'base64');
  }

  // verify signature with public key
  verifySignature(data: Buffer, signature: string, publicKey: string): boolean {
    try {
      const verify = crypto.createVerify('SHA256');
      verify.update(data);
      verify.end();
      return verify.verify(publicKey, signature, 'base64');
    } catch (error) {
      return false;
    }
  }

  parseCertificate(certJson: string): any {
    try {
      return JSON.parse(certJson);
    } catch {
      return null;
    }
  }

  validateCertificate(certJson: string, caCertJson?: string): boolean {
    const cert = this.parseCertificate(certJson);
    if (!cert) return false;

    // check expiration
    const now = new Date();
    if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) {
      return false;
    }

    // if CA cert provided, verify signature
    if (caCertJson) {
      const caCert = this.parseCertificate(caCertJson);
      if (!caCert) return false;

      const dataToVerify = Buffer.from(cert.publicKey + cert.subject);
      return this.verifySignature(dataToVerify, cert.signature, caCert.publicKey);
    }

    // for self-signed, verify with own public key
    const dataToVerify = Buffer.from(cert.publicKey + cert.subject);
    return this.verifySignature(dataToVerify, cert.signature, cert.publicKey);
  }
}
