import { Injectable, Inject, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { createCipheriv, createDecipheriv } from 'crypto';
import { HandshakeService } from '../handshake/handshake.service';

interface SecureSession {
  nodeId: string;
  keys: SessionKeys;
  sequenceNumber: number;
  lastReceivedSeqNum: number;
  establishedAt: Date;
}

interface SessionKeys {
  encryptionKey: Buffer;
  ivSeed: Buffer;
  hmacKey: Buffer;
}

export interface Message {
  content: string;
  timestamp: number;
  sequenceNumber: number;
}

@Injectable()
export class SecureChannelService {
  private readonly logger = new Logger('SecureChannelService');
  private sessions:  Map<string, SecureSession> = new Map();
  private messageQueues: Map<string, Message[]> = new Map();

  constructor(
    @Inject('NODE_ID') private readonly nodeId: string,
    private readonly handshakeService: HandshakeService,
    private readonly httpService: HttpService,
  ) {}

  async sendSecureMessage(toNodeId: string, message: string) {
    this.logger.log(`\n=== SENDING SECURE MESSAGE:  ${this.nodeId} -> ${toNodeId} ===`);
    this.logger.log(`  Message: "${message}"`);
    this.logger.log(`  Length: ${message.length} bytes`);

    let session = this.sessions.get(toNodeId);

    if (!session) {
      const sessionKeys = this.handshakeService.getSessionKeys(toNodeId);

      if (!sessionKeys) {
        throw new Error(`No secure session established with ${toNodeId}.  Perform handshake first.`);
      }

      session = {
        nodeId: toNodeId,
        keys: sessionKeys,
        sequenceNumber: 0,
        lastReceivedSeqNum: 0,
        establishedAt: new Date(),
      };

      this.sessions.set(toNodeId, session);
    }

    session.sequenceNumber++;

    const iv = Buffer.alloc(16);
    session.keys.ivSeed. copy(iv);
    iv.writeUInt32BE(session. sequenceNumber, 12);

    this.logger.log(`  Sequence Number: ${session.sequenceNumber}`);
    this.logger.log(`  IV: ${iv.toString('hex')}`);

    const cipher = createCipheriv('aes-256-gcm', session. keys.encryptionKey, iv);

    let ciphertext = cipher.update(message, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);

    const authTag = cipher.getAuthTag();

    this.logger.log(`  Ciphertext: ${ciphertext.toString('hex').substring(0, 50)}...`);
    this.logger.log(`  Auth Tag: ${authTag.toString('hex')}`);
    this.logger.log('  ✓ Message encrypted (AES-256-GCM)');

    const encryptedMessage = {
      type: 'secure-message',
      fromNodeId: this.nodeId,
      toNodeId:  toNodeId,
      sequenceNumber: session.sequenceNumber,
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag. toString('base64'),
      timestamp: Date.now(),
    };

    try {
      await firstValueFrom(
        this.httpService.post(`http://localhost:${this.getPortForNode(toNodeId)}/secure/receive`, encryptedMessage)
      );

      this.logger.log('  ✓ Message sent successfully');

      return {
        success: true,
        sequenceNumber: session.sequenceNumber,
      };
    } catch (error) {
      this.logger.error(`  ✗ Failed to send message: ${error.message}`);
      throw error;
    }
  }

  async receiveSecureMessage(packet: any) {
    this.logger.log(`\n=== RECEIVING SECURE MESSAGE from ${packet.fromNodeId} ===`);

    const fromNodeId = packet.fromNodeId;

    let session = this.sessions.get(fromNodeId);

    if (!session) {
      const sessionKeys = this.handshakeService.getSessionKeys(fromNodeId);

      if (!sessionKeys) {
        throw new Error(`No secure session with ${fromNodeId}`);
      }

      session = {
        nodeId: fromNodeId,
        keys: sessionKeys,
        sequenceNumber: 0,
        lastReceivedSeqNum: 0,
        establishedAt: new Date(),
      };

      this.sessions.set(fromNodeId, session);
    }

    if (packet.sequenceNumber <= session.lastReceivedSeqNum) {
      this.logger.warn('  ✗ Invalid sequence number - possible replay attack');
      throw new Error('Invalid sequence number');
    }

    const ciphertext = Buffer.from(packet.ciphertext, 'base64');
    const iv = Buffer.from(packet.iv, 'base64');
    const authTag = Buffer.from(packet. authTag, 'base64');

    this.logger.log(`  Sequence Number: ${packet.sequenceNumber}`);
    this.logger.log(`  Ciphertext length: ${ciphertext.length} bytes`);

    try {
      const decipher = createDecipheriv('aes-256-gcm', session.keys.encryptionKey, iv);
      decipher.setAuthTag(authTag);

      let plaintext = decipher.update(ciphertext);
      plaintext = Buffer.concat([plaintext, decipher. final()]);

      const message = plaintext.toString('utf8');

      this.logger.log(`  Decrypted message: "${message}"`);
      this.logger.log('  ✓ Message decrypted and verified');

      session.lastReceivedSeqNum = packet.sequenceNumber;

      if (! this.messageQueues.has(fromNodeId)) {
        this.messageQueues.set(fromNodeId, []);
      }

      this.messageQueues.get(fromNodeId).push({
        content: message,
        timestamp: packet.timestamp,
        sequenceNumber: packet.sequenceNumber,
      });

      this.logger. log(`  Messages from ${fromNodeId}: ${this. messageQueues.get(fromNodeId).length}`);

      return {
        success: true,
        message,
        sequenceNumber: packet. sequenceNumber,
      };
    } catch (error) {
      this.logger.error('  ✗ Decryption failed - authentication tag invalid');
      throw new Error('Message authentication failed');
    }
  }

  getMessages(fromNodeId: string): Message[] {
    return this.messageQueues.get(fromNodeId) || [];
  }

  clearMessages(fromNodeId: string): void {
    this.messageQueues.delete(fromNodeId);
  }

  getActiveSessions() {
    return Array.from(this.sessions.values()).map(session => ({
      nodeId: session.nodeId,
      establishedAt: session.establishedAt,
      sequenceNumber: session.sequenceNumber,
    }));
  }

  private getPortForNode(nodeId: string): number {
    const portMap = {
      node1: 3000,
      node2: 3001,
      node3: 3002,
      node4: 3003,
      node5: 3004,
    };
    return portMap[nodeId] || 3000;
  }
}
