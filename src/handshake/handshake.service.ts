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
    return {
      clientRandom: this.cryptoService.generateRandomBytes(32),
    };
  }

  generateServerHello(
    nodeId: string,
    publicKey: string,
    privateKey: string
  ): ServerHello {
    const serverRandom = this.cryptoService.generateRandomBytes(32);

    // sign certificate with CA
    const certificate = this.caService.signServerCertificate(
      publicKey,
      `CN=${nodeId},O=TLS Node`
    );

    return {
      serverRandom,
      certificate,
    };
  }

  encryptPremasterSecret(publicKey: string): {
    premasterSecret: Buffer;
    encrypted: EncryptedPremaster;
  } {
    const premasterSecret = this.cryptoService.generateRandomBytes(48);
    const payload = this.cryptoService.rsaEncrypt(premasterSecret, publicKey);

    return {
      premasterSecret,
      encrypted: { payload },
    };
  }

  decryptPremasterSecret(
    encrypted: EncryptedPremaster,
    privateKey: string
  ): Buffer {
    return this.cryptoService.rsaDecrypt(encrypted.payload, privateKey);
  }

  deriveSessionKeys(
    premasterSecret: Buffer,
    clientRandom: Buffer,
    serverRandom: Buffer
  ): SessionKeys {
    const keys = this.cryptoService.deriveSessionKeys(
      premasterSecret,
      clientRandom,
      serverRandom
    );

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
    const plaintext = Buffer.from(message);
    const iv = this.cryptoService.generateIV(sessionKeys.ivSeed, sequenceNumber);
    const { ciphertext, authTag } = this.cryptoService.aesEncrypt(
      plaintext,
      sessionKeys.encryptionKey,
      iv
    );

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
    try {
      const decrypted = this.cryptoService.aesDecrypt(
        finished.encryptedPayload,
        sessionKeys.encryptionKey,
        finished.iv,
        finished.authTag
      );

      return decrypted.toString() === expectedMessage;
    } catch (error) {
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
