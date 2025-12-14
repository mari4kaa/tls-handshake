import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { CryptoService } from '../crypto/crypto.service';
import { HandshakeService } from '../handshake/handshake.service';
import { TransportService } from '../transport/transport.service';
import { RoutingService } from '../routing/routing.service';
import { SecureChannelService } from '../secure-channel/secure-channel.service';
import {
  ClientHello,
  ServerHello,
  EncryptedPremaster,
  FinishedMessage,
  SecureMessage,
  SessionKeys,
  NetworkPacket,
} from '../types';
import * as http from 'http';
import { serializeBuffers, deserializeBuffers } from '../utils';

interface PeerSession {
  sessionId: string;
  sessionKeys?: SessionKeys;
  isHandshakeComplete: boolean;
}

@Injectable()
export class NetworkNodeService {
  private nodeId: string;
  private port: number;
  private publicKey: string;
  private privateKey: string;
  private peerSessions: Map<string, PeerSession> = new Map();
  private messageQueue: Map<string, Buffer[]> = new Map();

  constructor(
    private cryptoService: CryptoService,
    private handshakeService: HandshakeService,
    private transportService: TransportService,
    private routingService: RoutingService,
    private secureChannelService: SecureChannelService
  ) {}

  initialize(nodeId: string, port: number): void {
    this.nodeId = nodeId;
    this.port = port;

    const keyPair = this.cryptoService.generateRSAKeyPair();
    this.publicKey = keyPair.publicKey;
    this.privateKey = keyPair.privateKey;

    this.routingService.addNode(nodeId);

    console.log(`Node ${nodeId} initialized on port ${port}`);
  }

  getNodeId(): string {
    return this.nodeId;
  }

  getPublicKey(): string {
    return this.publicKey;
  }

  handleClientHello(fromNode: string, clientHello: ClientHello): ServerHello {
    const sessionId = this.handshakeService.startServerHandshake(
      this.nodeId,
      fromNode
    );

    this.handshakeService.updateClientRandom(sessionId, clientHello.clientRandom);

    const serverHello = this.handshakeService.generateServerHello(
      this.nodeId,
      this.publicKey,
      this.privateKey
    );

    this.handshakeService.updateServerRandom(sessionId, serverHello.serverRandom);

    this.peerSessions.set(fromNode, {
      sessionId,
      isHandshakeComplete: false,
    });

    return serverHello;
  }

  handleServerHello(
    toNode: string,
    serverHello: ServerHello,
    clientRandom: Buffer
  ): EncryptedPremaster {
    const isValid = this.handshakeService.verifyCertificate(
      serverHello.certificate
    );

    if (!isValid) {
      throw new HttpException(
        'Certificate validation failed',
        HttpStatus.UNAUTHORIZED
      );
    }

    // public key from certificate
    const cert = this.cryptoService.parseCertificate(serverHello.certificate);
    const serverPublicKey = cert.publicKey;

    let sessionId = this.peerSessions.get(toNode)?.sessionId;
    if (!sessionId) {
      sessionId = this.handshakeService.startClientHandshake(this.nodeId, toNode);
    }

    // Store randoms
    this.handshakeService.updateClientRandom(sessionId, clientRandom);
    this.handshakeService.updateServerRandom(sessionId, serverHello.serverRandom);

    // Generate and encrypt premaster
    const { premasterSecret, encrypted } =
      this.handshakeService.encryptPremasterSecret(serverPublicKey);

    // Store premaster
    this.handshakeService.updatePremasterSecret(sessionId, premasterSecret);

    this.peerSessions.set(toNode, {
      sessionId,
      isHandshakeComplete: false,
    });

    return encrypted;
  }

  handleEncryptedPremaster(
    fromNode: string,
    encrypted: EncryptedPremaster
  ): FinishedMessage {
    const peerSession = this.peerSessions.get(fromNode);
    if (!peerSession) {
      throw new HttpException('No handshake session', HttpStatus.BAD_REQUEST);
    }

    // Decrypt premaster
    const premasterSecret = this.handshakeService.decryptPremasterSecret(
      encrypted,
      this.privateKey
    );

    // Store premaster and complete handshake
    this.handshakeService.updatePremasterSecret(
      peerSession.sessionId,
      premasterSecret
    );
    this.handshakeService.completeHandshake(peerSession.sessionId);

    const session = this.handshakeService.getSession(peerSession.sessionId);
    if (!session || !session.sessionKeys) {
      throw new HttpException(
        'Failed to derive session keys',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }

    peerSession.sessionKeys = session.sessionKeys;

    const finishedMessage = this.handshakeService.createFinishedMessage(
      'server finished',
      session.sessionKeys,
      0
    );

    return finishedMessage;
  }

  handleFinishedMessage(
    fromNode: string,
    finished: FinishedMessage,
    isClient: boolean
  ): FinishedMessage | null {
    const peerSession = this.peerSessions.get(fromNode);
    if (!peerSession) {
      throw new HttpException('No handshake session', HttpStatus.BAD_REQUEST);
    }

    if (!peerSession.sessionKeys) {
      this.handshakeService.completeHandshake(peerSession.sessionId);
      const session = this.handshakeService.getSession(peerSession.sessionId);
      if (session && session.sessionKeys) {
        peerSession.sessionKeys = session.sessionKeys;
      }
    }

    if (!peerSession.sessionKeys) {
      throw new HttpException(
        'Session keys not available',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }

    const expectedMessage = isClient ? 'server finished' : 'client finished';
    const isValid = this.handshakeService.verifyFinishedMessage(
      finished,
      peerSession.sessionKeys,
      expectedMessage
    );

    if (!isValid) {
      throw new HttpException(
        'Finished message verification failed',
        HttpStatus.UNAUTHORIZED
      );
    }

    peerSession.isHandshakeComplete = true;

    console.log(`Handshake complete between ${this.nodeId} and ${fromNode}`);

    // If server, we already sent finished, return null
    // If client, send our finished message
    if (isClient) {
      return this.handshakeService.createFinishedMessage(
        'client finished',
        peerSession.sessionKeys,
        1
      );
    }

    return null;
  }

  async initiateHandshake(targetNode: string, targetPort: number): Promise<void> {
    console.log(`${this.nodeId} initiating handshake with ${targetNode}`);

    // Generate ClientHello
    const clientHello = this.handshakeService.generateClientHello();
    const sessionId = this.handshakeService.startClientHandshake(
      this.nodeId,
      targetNode
    );

    this.handshakeService.updateClientRandom(sessionId, clientHello.clientRandom);

    this.peerSessions.set(targetNode, {
      sessionId,
      isHandshakeComplete: false,
    });

    // Send ClientHello to target node
    const serverHello = await this.sendHttpRequest<ServerHello>(
      targetNode,
      targetPort,
      '/handshake/client-hello',
      {
        fromNode: this.nodeId,
        clientHello,
      }
    );

    // Process ServerHello
    const encryptedPremaster = this.handleServerHello(
      targetNode,
      serverHello,
      clientHello.clientRandom
    );

    // Send EncryptedPremaster
    const serverFinished = await this.sendHttpRequest<FinishedMessage>(
      targetNode,
      targetPort,
      '/handshake/encrypted-premaster',
      {
        fromNode: this.nodeId,
        encryptedPremaster,
      }
    );

    // Process server finished and send client finished
    const clientFinished = this.handleFinishedMessage(
      targetNode,
      serverFinished,
      true
    );

    if (clientFinished) {
      await this.sendHttpRequest(
        targetNode,
        targetPort,
        '/handshake/finished',
        {
          fromNode: this.nodeId,
          finished: clientFinished,
        }
      );
    }

    console.log(`Handshake completed: ${this.nodeId} <-> ${targetNode}`);
  }

  async sendSecureMessage(
    targetNode: string,
    message: string,
    targetPort?: number
  ): Promise<void> {
    const peerSession = this.peerSessions.get(targetNode);
    
    if (!peerSession || !peerSession.isHandshakeComplete || !peerSession.sessionKeys) {
      throw new HttpException(
        'No secure channel established with target node',
        HttpStatus.BAD_REQUEST
      );
    }

    const messageBuffer = Buffer.from(message);
    const channelId = `${this.nodeId}-${targetNode}`;

    const secureMessage = this.secureChannelService.encryptMessage(
      messageBuffer,
      peerSession.sessionKeys,
      channelId
    );

    // Get route to target
    const route = this.routingService.findRoute(this.nodeId, targetNode);
    if (!route || route.path.length < 2) {
      throw new HttpException('No route to target node', HttpStatus.NOT_FOUND);
    }

    const nextHop = route.path[1];
    const link = this.routingService.getLink(this.nodeId, nextHop);
    
    if (!link) {
      throw new HttpException('No link to next hop', HttpStatus.NOT_FOUND);
    }

    // Fragment message if needed
    const payload = Buffer.from(JSON.stringify(secureMessage));
    const packets = this.transportService.fragmentMessage(
      this.nodeId,
      targetNode,
      payload,
      link.mtu,
      secureMessage.sequenceNumber
    );

    // Send packets
    for (const packet of packets) {
      // Apply delay if configured
      if (link.delay) {
        await this.transportService.applyDelay(link.delay);
      }

      // Simulate packet loss
      if (link.packetLoss && this.transportService.shouldDropPacket(link.packetLoss)) {
        console.log(`Packet dropped due to simulated loss`);
        continue;
      }

      // Route packet
      await this.routePacket(packet, targetPort || this.port);
    }
  }

  private async routePacket(packet: NetworkPacket, port: number): Promise<void> {
    if (packet.destination === this.nodeId) {
      // Packet reached destination
      this.handleIncomingPacket(packet);
      return;
    }

    const nextHop = this.routingService.getNextHop(this.nodeId, packet.destination);
    if (!nextHop) {
      console.error(`No route to ${packet.destination}`);
      return;
    }

    // Forward packet to next hop
    await this.sendHttpRequest(
      nextHop,
      port,
      '/network/route',
      { packet }
    );
  }

  handleIncomingPacket(packet: NetworkPacket): void {
    // Reassemble if fragmented
    const payload = this.transportService.reassembleFragments(packet);
    
    if (!payload) {
      return;
    }

    const parsed = JSON.parse(payload.toString());
    const secureMessage: SecureMessage = deserializeBuffers(parsed);
    
    const peerSession = this.peerSessions.get(packet.source);
    if (!peerSession || !peerSession.sessionKeys) {
      console.error('No session keys for peer');
      return;
    }

    // Decrypt message
    const decrypted = this.secureChannelService.decryptMessage(
      secureMessage,
      peerSession.sessionKeys
    );

    console.log(`[${this.nodeId}] Received secure message from ${packet.source}: ${decrypted.toString()}`);

    // Store in message queue
    if (!this.messageQueue.has(packet.source)) {
      this.messageQueue.set(packet.source, []);
    }
    this.messageQueue.get(packet.source)!.push(decrypted);
  }

  async broadcastMessage(message: string, port: number): Promise<void> {
    const visitedNodes = [this.nodeId];
    const targets = this.routingService.getBroadcastTargets(
      this.nodeId,
      visitedNodes
    );

    for (const target of targets) {
      try {
        await this.sendHttpRequest(
          target,
          port,
          '/network/broadcast',
          {
            fromNode: this.nodeId,
            message: Buffer.from(message),
            visitedNodes,
          }
        );
      } catch (error) {
        console.error(`Failed to broadcast to ${target}:`, error.message);
      }
    }
  }

  async handleBroadcast(
    fromNode: string,
    message: Buffer,
    visitedNodes: string[],
    port: number
  ): Promise<void> {
    if (visitedNodes.includes(this.nodeId)) {
      return;
    }
    
    console.log(`[${this.nodeId}] Received broadcast from ${fromNode}: ${message.toString()}`);

    // Add self to visited
    const newVisited = [...visitedNodes, this.nodeId];

    // Forward to neighbors
    const targets = this.routingService.getBroadcastTargets(
      this.nodeId,
      newVisited
    );

    for (const target of targets) {
      try {
        await this.sendHttpRequest(
          target,
          port,
          '/network/broadcast',
          {
            fromNode: this.nodeId,
            message,
            visitedNodes: newVisited,
          }
        );
      } catch (error) {
        console.error(`Failed to forward broadcast to ${target}:`, error.message);
      }
    }
  }

  getMessages(fromNode: string): string[] {
    const messages = this.messageQueue.get(fromNode) || [];
    return messages.map(m => m.toString());
  }

  clearMessages(fromNode: string): void {
    this.messageQueue.set(fromNode, []);
  }

  getPeerSessions(): Map<string, PeerSession> {
    return this.peerSessions;
  }

  private sendHttpRequest<T = any>(
    targetNode: string,
    port: number,
    path: string,
    data: any
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      // Serialize buffers before sending
      const serializedData = serializeBuffers(data);
      const postData = JSON.stringify(serializedData);

      const options = {
        hostname: 'localhost',
        port,
        path,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
        },
      };

      const req = http.request(options, (res) => {
        let responseData = '';

        res.on('data', (chunk) => {
          responseData += chunk;
        });

        res.on('end', () => {
          try {
            const parsed = JSON.parse(responseData);
            // Deserialize buffers in response
            const deserialized = deserializeBuffers(parsed);
            resolve(deserialized);
          } catch (error) {
            reject(new Error('Invalid JSON response'));
          }
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      req.write(postData);
      req.end();
    });
  }
}
