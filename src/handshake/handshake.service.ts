import { Injectable } from '@nestjs/common';
import { CryptoService } from '../crypto/crypto.service';
import { CertificateAuthorityService } from '../ca/ca.service';
import {
  ClientHello,
  ServerHello,
  EncryptedPremaster,
  FinishedMessage,
  HandshakeSession,
  SessionKeys,
} from '../types';

@Injectable()
export class HandshakeService {
  private sessions: Map<string, HandshakeSession> = new Map();

  constructor(
    private cryptoService: CryptoService,
    private caService: CertificateAuthorityService
  ) {}

  generateClientHello(): ClientHello {
    const clientRandom = this.cryptoService.generateRandomBytes(32);
    console.log('=== HANDSHAKE STEP 1: Client Hello Generation ===');
    console.log('ClientHello generated:');
    console.log(`  - Client Random (hex): ${clientRandom.toString('hex')}`);
    console.log(`  - Client Random (base64): ${clientRandom.toString('base64')}`);
    console.log(`  - Random bytes length: ${clientRandom.length} bytes`);
    return {
      clientRandom,
    };
  }

  generateServerHello(
    nodeId: string,
    publicKey: string,
    privateKey: string
  ): ServerHello {
    console.log('=== HANDSHAKE STEP 2: Server Hello Generation ===');
    const serverRandom = this.cryptoService.generateRandomBytes(32);
    console.log('ServerHello components:');
    console.log(`  - Server Random (hex): ${serverRandom.toString('hex')}`);
    console.log(`  - Server Random (base64): ${serverRandom.toString('base64')}`);
    console.log(`  - Random bytes length: ${serverRandom.length} bytes`);

    console.log('\nGenerating X.509-style SSL Certificate for server...');
    console.log(`  - Node ID: ${nodeId}`);
    console.log(`  - Server Public Key: ${publicKey}...`);
    console.log(`  - Server Public Key length: ${publicKey.length} characters`);

    // sign certificate with CA
    const certificate = this.caService.signServerCertificate(
      publicKey,
      `CN=${nodeId},O=TLS Node`
    );

    console.log('\nCertificate Generated and Signed by CA:');
    const certObj = JSON.parse(certificate);
    console.log(`  - Version: ${certObj.version}`);
    console.log(`  - Serial Number: ${certObj.serialNumber}`);
    console.log(`  - Subject: ${certObj.subject}`);
    console.log(`  - Issuer: ${certObj.issuer}`);
    console.log(`  - Valid From: ${certObj.validFrom}`);
    console.log(`  - Valid To: ${certObj.validTo}`);
    console.log(`  - Public Key: ${certObj.publicKey}...`);
    console.log(`  - Signature: ${certObj.signature}...`);
    console.log(`  - Signature length: ${certObj.signature.length} characters`);
    console.log(`  - Full certificate (JSON): ${certificate}...`);

    return {
      serverRandom,
      certificate,
    };
  }

  encryptPremasterSecret(publicKey: string): {
    premasterSecret: Buffer;
    encrypted: EncryptedPremaster;
  } {
    console.log('=== HANDSHAKE STEP 4: Premaster Secret Encryption ===');
    const premasterSecret = this.cryptoService.generateRandomBytes(48);
    console.log('Premaster Secret Generation:');
    console.log(`  - Premaster Secret (hex): ${premasterSecret.toString('hex')}`);
    console.log(`  - Premaster Secret (base64): ${premasterSecret.toString('base64')}`);
    console.log(`  - Premaster Secret length: ${premasterSecret.length} bytes`);
    
    console.log('\nRSA Encryption (RSA-OAEP-SHA256):');
    console.log(`  - Public Key (from verified certificate) length: ${publicKey.length} characters`);
    console.log(`  - Public Key: ${publicKey}`);
    console.log(`  - Algorithm: RSA-OAEP with SHA-256`);
    
    const payload = this.cryptoService.rsaEncrypt(premasterSecret, publicKey);
    console.log(`  - Encrypted payload length: ${payload.length} bytes`);
    console.log(`  - Encrypted payload: ${payload.toString('base64')}...`);

    return {
      premasterSecret,
      encrypted: { payload },
    };
  }

  decryptPremasterSecret(
    encrypted: EncryptedPremaster,
    privateKey: string
  ): Buffer {
    console.log('=== HANDSHAKE: Server Decrypting Premaster Secret ===');
    console.log('RSA Decryption (RSA-OAEP-SHA256):');
    console.log(`  - Encrypted payload length: ${encrypted.payload.length} bytes`);
    console.log(`  - Encrypted payload: ${encrypted.payload.toString('base64')}...`);
    console.log(`  - Private Key length: ${privateKey.length} characters`);
    console.log(`  - Algorithm: RSA-OAEP with SHA-256`);
    
    const decrypted = this.cryptoService.rsaDecrypt(encrypted.payload, privateKey);
    console.log('\nDecryption Result:');
    console.log(`  - Decrypted Premaster Secret (hex): ${decrypted.toString('hex')}`);
    console.log(`  - Decrypted Premaster Secret (base64): ${decrypted.toString('base64')}`);
    console.log(`  - Decrypted length: ${decrypted.length} bytes`);
    
    return decrypted;
  }

  deriveSessionKeys(
    premasterSecret: Buffer,
    clientRandom: Buffer,
    serverRandom: Buffer
  ): SessionKeys {
    console.log('=== HANDSHAKE STEP 5: Session Key Derivation (HKDF-SHA256) ===');
    console.log('Input Materials:');
    console.log(`  - Premaster Secret (hex): ${premasterSecret.toString('hex')}`);
    console.log(`  - Client Random (hex): ${clientRandom.toString('hex')}`);
    console.log(`  - Server Random (hex): ${serverRandom.toString('hex')}`);
    console.log(`  - Key Derivation Function: HKDF-SHA256`);

    const keys = this.cryptoService.deriveSessionKeys(
      premasterSecret,
      clientRandom,
      serverRandom
    );

    console.log('\nDerived Session Keys:');
    console.log(`  - Encryption Key (AES-256, hex): ${keys.encryptionKey.toString('hex')}`);
    console.log(`  - Encryption Key length: ${keys.encryptionKey.length} bytes (${keys.encryptionKey.length * 8} bits)`);
    console.log(`  - IV Seed (hex): ${keys.ivSeed.toString('hex')}`);
    console.log(`  - IV Seed length: ${keys.ivSeed.length} bytes`);
    console.log(`  - HMAC Key (hex): ${keys.hmacKey.toString('hex')}`);
    console.log(`  - HMAC Key length: ${keys.hmacKey.length} bytes (${keys.hmacKey.length * 8} bits)`);
    console.log(`  - Total key material: ${keys.encryptionKey.length + keys.ivSeed.length + keys.hmacKey.length} bytes`);

    return {
      encryptionKey: keys.encryptionKey,
      ivSeed: keys.ivSeed,
      hmacKey: keys.hmacKey,
    };
  }

  createFinishedMessage(
    message: string,
    sessionKeys: SessionKeys,
    sequenceNumber: number
  ): FinishedMessage {
    console.log('=== HANDSHAKE STEP 6: Creating Finished Message (AES-256-GCM) ===');
    console.log('Message Encryption:');
    console.log(`  - Plaintext message: "${message}"`);
    console.log(`  - Plaintext length: ${message.length} characters`);
    console.log(`  - Sequence number: ${sequenceNumber}`);
    
    const plaintext = Buffer.from(message);
    const iv = this.cryptoService.generateIV(sessionKeys.ivSeed, sequenceNumber);
    console.log(`  - Generated IV (hex): ${iv.toString('hex')}`);
    console.log(`  - IV length: ${iv.length} bytes`);
    console.log(`  - Using encryption key: ${sessionKeys.encryptionKey.toString('hex')}...`);
    
    const { ciphertext, authTag } = this.cryptoService.aesEncrypt(
      plaintext,
      sessionKeys.encryptionKey,
      iv
    );

    console.log('\nEncryption Result:');
    console.log(`  - Ciphertext (hex): ${ciphertext.toString('hex')}`);
    console.log(`  - Ciphertext (base64): ${ciphertext.toString('base64')}`);
    console.log(`  - Ciphertext length: ${ciphertext.length} bytes`);
    console.log(`  - Auth Tag (hex): ${authTag.toString('hex')}`);
    console.log(`  - Auth Tag length: ${authTag.length} bytes`);
    console.log(`  - Algorithm: AES-256-GCM with authentication`);

    return {
      encryptedPayload: ciphertext,
      iv,
      authTag,
    };
  }

  verifyFinishedMessage(
    finished: FinishedMessage,
    sessionKeys: SessionKeys,
    expectedMessage: string
  ): boolean {
    console.log('=== HANDSHAKE STEP 6: Verifying Finished Message ===');
    console.log('Decryption and Verification:');
    console.log(`  - Ciphertext (hex): ${finished.encryptedPayload.toString('hex')}`);
    console.log(`  - Ciphertext length: ${finished.encryptedPayload.length} bytes`);
    console.log(`  - IV (hex): ${finished.iv.toString('hex')}`);
    console.log(`  - Auth Tag (hex): ${finished.authTag.toString('hex')}`);
    console.log(`  - Expected message: "${expectedMessage}"`);

    try {
      const decrypted = this.cryptoService.aesDecrypt(
        finished.encryptedPayload,
        sessionKeys.encryptionKey,
        finished.iv,
        finished.authTag
      );

      const decryptedText = decrypted.toString();
      const isValid = decryptedText === expectedMessage;
      
      console.log('\nVerification Result:');
      console.log(`  - Decrypted message: "${decryptedText}"`);
      console.log(`  - Expected message: "${expectedMessage}"`);
      console.log(`  - Messages match: ${isValid ? 'YES ✓' : 'NO ✗'}`);
      console.log(`  - Auth tag verified: ${isValid ? 'YES ✓' : 'NO ✗'}`);
      console.log(`  - Handshake verification: ${isValid ? 'SUCCESS ✓' : 'FAILED ✗'}`);

      return isValid;
    } catch (error) {
      console.log('\nVerification Result: FAILED ✗');
      console.log(`  - Error: ${error.message}`);
      console.log(`  - Authentication tag validation failed or decryption error`);
      return false;
    }
  }

  startClientHandshake(localNodeId: string, remoteNodeId: string): string {
    const sessionId = `${localNodeId}-${remoteNodeId}-${Date.now()}`;
    const session: HandshakeSession = {
      nodeId: remoteNodeId,
      isComplete: false,
      isClient: true,
    };

    this.sessions.set(sessionId, session);
    return sessionId;
  }

  startServerHandshake(localNodeId: string, remoteNodeId: string): string {
    const sessionId = `${localNodeId}-${remoteNodeId}-${Date.now()}`;
    const session: HandshakeSession = {
      nodeId: remoteNodeId,
      isComplete: false,
      isClient: false,
    };

    this.sessions.set(sessionId, session);
    return sessionId;
  }

  updateClientRandom(sessionId: string, clientRandom: Buffer): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.clientRandom = clientRandom;
    }
  }

  updateServerRandom(sessionId: string, serverRandom: Buffer): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.serverRandom = serverRandom;
    }
  }

  updatePremasterSecret(sessionId: string, premasterSecret: Buffer): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.premasterSecret = premasterSecret;
    }
  }

  completeHandshake(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session && session.clientRandom && session.serverRandom && session.premasterSecret) {
      session.sessionKeys = this.deriveSessionKeys(
        session.premasterSecret,
        session.clientRandom,
        session.serverRandom
      );
      session.isComplete = true;
    }
  }

  getSession(sessionId: string): HandshakeSession | undefined {
    return this.sessions.get(sessionId);
  }

  verifyCertificate(certificate: string): boolean {
    return this.caService.verifyCertificate(certificate);
  }
}
