import { Injectable, Inject, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { createCipheriv, createDecipheriv } from 'crypto';
import { HandshakeService } from '../handshake/handshake.service';
import { TransportService } from '../transport/transport.service';
import { NetworkPacket } from '../types';

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
  private sessions: Map<string, SecureSession> = new Map();
  private messageQueues: Map<string, Message[]> = new Map();

  constructor(
    @Inject('NODE_ID') private readonly nodeId: string,
    private readonly handshakeService: HandshakeService,
    private readonly httpService: HttpService,
    private readonly transportService: TransportService,
  ) {}

  async sendSecureMessage(toNodeId: string, message: string, options?:  { mtu?: number }) {
    this.logger.log(`\n=== SENDING SECURE MESSAGE:  ${this.nodeId} -> ${toNodeId} ===`);
    this.logger.log(`  Message:  "${message. substring(0, 50)}${message.length > 50 ?  '...' : ''}"`);
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
        sequenceNumber:  0,
        lastReceivedSeqNum: 0,
        establishedAt: new Date(),
      };

      this. sessions.set(toNodeId, session);
    }

    session.sequenceNumber++;

    const iv = Buffer.alloc(16);
    session.keys.ivSeed. copy(iv);
    iv.writeUInt32BE(session.sequenceNumber, 12);

    this.logger.log(`  Sequence Number: ${session.sequenceNumber}`);
    this.logger.log(`  IV:  ${iv.toString('hex')}`);

    const cipher = createCipheriv('aes-256-gcm', session. keys.encryptionKey, iv);

    let ciphertext = cipher.update(message, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);

    const authTag = cipher.getAuthTag();

    this.logger.log(`  Ciphertext:  ${ciphertext.toString('hex').substring(0, 50)}...`);
    this.logger.log(`  Auth Tag: ${authTag.toString('hex')}`);
    this.logger.log('  ✓ Message encrypted (AES-256-GCM)');

    const encryptedMessage = {
      type: 'secure-message',
      fromNodeId: this.nodeId,
      toNodeId:  toNodeId,
      sequenceNumber: session.sequenceNumber,
      ciphertext: ciphertext. toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag. toString('base64'),
      timestamp: Date.now(),
    };

    // Serialize encrypted message to buffer
    const payload = Buffer.from(JSON.stringify(encryptedMessage));
    
    this.logger.log(`\n  Encrypted payload size: ${payload.length} bytes`);

    // *** USE TRANSPORT SERVICE FOR FRAGMENTATION ***
    const mtu = options?.mtu || 1500; // Default MTU 1500 bytes
    this.logger.log(`  MTU limit: ${mtu} bytes`);

    const packets = this.transportService.fragmentMessage(
      this.nodeId,
      toNodeId,
      payload,
      mtu,
      session.sequenceNumber
    );

    if (packets.length > 1) {
      this.logger. log(`\n  ✓ Message fragmented into ${packets.length} packets`);
      for (let i = 0; i < packets.length; i++) {
        this.logger.log(`    Fragment ${i + 1}/${packets.length}:  ${packets[i].payload.length} bytes`);
      }
    } else {
      this.logger.log(`  ✓ Message fits in single packet (no fragmentation needed)`);
    }

    this.logger.log(`\n  Sending ${packets.length} packet(s) to ${toNodeId}...`);

    // Send each packet
    let sentCount = 0;
    for (const packet of packets) {
      try {
        await firstValueFrom(
          this.httpService.post(
            `http://localhost:${this.getPortForNode(toNodeId)}/secure/receive-packet`,
            this.serializePacket(packet)
          )
        );

        sentCount++;
        
        if (packet.isFragment) {
          this.logger.log(`    ✓ Fragment ${packet.fragmentIndex!  + 1}/${packet.totalFragments} sent`);
        } else {
          this.logger.log(`    ✓ Packet sent`);
        }

        // Small delay between fragments to simulate network
        if (packets.length > 1) {
          await this.transportService.applyDelay(10);
        }
      } catch (error) {
        this.logger.error(`    ✗ Failed to send packet:  ${error.message}`);
        throw error;
      }
    }

    this.logger.log(`\n  ✓ All ${sentCount} packet(s) sent successfully`);

    return {
      success: true,
      sequenceNumber: session.sequenceNumber,
      fragments: packets.length,
      totalBytes: payload.length,
    };
  }

  async receivePacket(packetData: any) {
    const packet = this.deserializePacket(packetData);

    if (packet.isFragment) {
      this.logger.log(`\n=== RECEIVING FRAGMENT from ${packet.source} ===`);
      this.logger.log(`  Fragment ${packet.fragmentIndex! + 1}/${packet.totalFragments}`);
      this.logger.log(`  Fragment ID: ${packet.fragmentId}`);
      this.logger.log(`  Payload size: ${packet.payload.length} bytes`);
    } else {
      this.logger.log(`\n=== RECEIVING PACKET from ${packet.source} ===`);
      this.logger.log(`  Payload size: ${packet.payload.length} bytes`);
    }

    // Try to reassemble
    const payload = this.transportService.reassembleFragments(packet);

    if (! payload) {
      // Still waiting for more fragments
      this.logger.log(`  ⏳ Waiting for more fragments...`);
      return {
        success: true,
        waiting: true,
        message: 'Fragment received, waiting for more',
      };
    }

    // All fragments received (or single packet), decrypt message
    this.logger.log(`\n  ✓ All fragments received, reassembled ${payload.length} bytes`);
    this.logger.log(`  Decrypting message...`);
    
    const parsed = JSON.parse(payload.toString());
    return await this.processSecureMessage(parsed);
  }

  private async processSecureMessage(packet: any) {
    this.logger.log(`\n=== DECRYPTING SECURE MESSAGE from ${packet.fromNodeId} ===`);

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
    const authTag = Buffer. from(packet.authTag, 'base64');

    this.logger.log(`  Sequence Number: ${packet.sequenceNumber}`);
    this.logger.log(`  Ciphertext length: ${ciphertext.length} bytes`);

    try {
      const decipher = createDecipheriv('aes-256-gcm', session.keys.encryptionKey, iv);
      decipher.setAuthTag(authTag);

      let plaintext = decipher.update(ciphertext);
      plaintext = Buffer.concat([plaintext, decipher. final()]);

      const message = plaintext.toString('utf8');

      this.logger.log(`  Decrypted message: "${message. substring(0, 50)}${message.length > 50 ?  '...' : ''}"`);
      this.logger.log(`  Message length: ${message.length} bytes`);
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

  async receiveSecureMessage(packet: any) {
    // Backward compatibility - treat as non-fragmented
    return await this.processSecureMessage(packet);
  }

  private serializePacket(packet: NetworkPacket): any {
    return {
      source: packet.source,
      destination: packet.destination,
      payload: packet.payload. toString('base64'),
      sequenceNumber:  packet.sequenceNumber,
      isFragment: packet.isFragment,
      fragmentId: packet.fragmentId,
      fragmentIndex: packet.fragmentIndex,
      totalFragments: packet.totalFragments,
    };
  }

  private deserializePacket(data: any): NetworkPacket {
    return {
      source: data.source,
      destination: data.destination,
      payload: Buffer.from(data.payload, 'base64'),
      sequenceNumber:  data.sequenceNumber,
      isFragment: data.isFragment,
      fragmentId: data.fragmentId,
      fragmentIndex: data.fragmentIndex,
      totalFragments: data.totalFragments,
    };
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

  private getPortForNode(nodeId:  string): number {
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
