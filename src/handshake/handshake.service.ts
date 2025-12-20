import { Injectable, Inject, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import {
  randomBytes,
  publicEncrypt,
  privateDecrypt,
  createCipheriv,
  createDecipheriv,
  hkdfSync,
} from 'crypto';
import { CaClientService } from '../network-node/ca-client.service';

interface HandshakeSession {
  clientRandom: Buffer;
  serverRandom?:  Buffer;
  premasterSecret?: Buffer;
  sessionKeys?:  SessionKeys;
  certificate?: any;
}

interface SessionKeys {
  encryptionKey: Buffer;
  ivSeed: Buffer;
  hmacKey: Buffer;
}

@Injectable()
export class HandshakeService {
  private readonly logger = new Logger('HandshakeService');
  private sessions: Map<string, HandshakeSession> = new Map();

  constructor(
    @Inject('NODE_ID') private readonly nodeId: string,
    private readonly caClientService: CaClientService,
    private readonly httpService: HttpService,
  ) {}

  async initiateHandshake(targetNodeId: string, targetUrl:  string) {
    this.logger.log(`\n=== INITIATING HANDSHAKE:  ${this.nodeId} -> ${targetNodeId} ===`);

    const clientRandom = randomBytes(32);
    this.logger.log('Step 1: ClientHello generated');
    this.logger.log(`  Client Random: ${clientRandom. toString('hex')}`);

    const session: HandshakeSession = { clientRandom };
    this.sessions.set(targetNodeId, session);

    this.logger.log('\nStep 2: Sending ClientHello to server.. .');
    const serverHelloResponse = await firstValueFrom(
      this.httpService.post(`${targetUrl}/handshake/client-hello`, {
        nodeId: this.nodeId,
        clientRandom:  clientRandom.toString('base64'),
      })
    );

    const { serverRandom, certificate } = serverHelloResponse.data;
    session.serverRandom = Buffer.from(serverRandom, 'base64');
    session.certificate = certificate;

    this.logger.log('  ServerHello received');
    this.logger.log(`  Server Random: ${session.serverRandom.toString('hex')}`);
    this.logger.log(`  Certificate: ${certificate.serialNumber}`);

    this.logger.log('\nStep 3: Verifying server certificate with CA...');
    const isValid = await this.caClientService.verifyCertificate(certificate);

    if (!isValid) {
      throw new Error('Certificate verification failed');
    }

    this.logger.log('  ✓ Certificate verified successfully');

    this.logger.log('\nStep 4: Generating premaster secret...');
    const premasterSecret = randomBytes(48);
    session.premasterSecret = premasterSecret;

    this.logger.log(`  Premaster Secret: ${premasterSecret.toString('hex')}`);
    this.logger.log('  Encrypting with server public key (RSA-OAEP-SHA256)...');

    const encryptedPremaster = publicEncrypt(
      {
        key: certificate.publicKey,
        padding: 1,
        oaepHash:  'sha256',
      },
      premasterSecret
    );

    this.logger.log(`  Encrypted size: ${encryptedPremaster. length} bytes`);

    this.logger.log('\nSending encrypted premaster to server...');
    await firstValueFrom(
      this. httpService.post(`${targetUrl}/handshake/encrypted-premaster`, {
        nodeId: this.nodeId,
        encryptedPremaster:  encryptedPremaster.toString('base64'),
      })
    );

    this.logger.log('\nStep 5: Deriving session keys (HKDF-SHA256)...');
    const sessionKeys = this.deriveSessionKeys(
      session.premasterSecret,
      session.clientRandom,
      session.serverRandom
    );
    session.sessionKeys = sessionKeys;

    this.logger.log('  ✓ Session keys derived');
    this.logger.log(`  Encryption Key: ${sessionKeys.encryptionKey.toString('hex')}`);
    this.logger.log(`  IV Seed: ${sessionKeys.ivSeed.toString('hex')}`);

    this.logger.log('\nStep 6: Sending encrypted "finished" message.. .');
    const finishedMessage = this.encryptFinishedMessage(sessionKeys, 'client finished', 1);

    await firstValueFrom(
      this.httpService.post(`${targetUrl}/handshake/finished`, {
        nodeId: this.nodeId,
        ... finishedMessage,
      })
    );

    this.logger.log('  ✓ Finished message sent');
    this.logger.log('\n=== HANDSHAKE COMPLETE ===');
    this.logger.log(`Secure channel established:  ${this.nodeId} <-> ${targetNodeId}`);

    return {
      success: true,
      sessionKeys,
      targetNodeId,
    };
  }

  async handleClientHello(fromNodeId: string, clientRandom: string) {
    this.logger.log(`\n=== HANDLING CLIENT HELLO from ${fromNodeId} ===`);

    const clientRandomBuffer = Buffer.from(clientRandom, 'base64');
    this.logger.log(`  Client Random: ${clientRandomBuffer.toString('hex')}`);

    const serverRandom = randomBytes(32);
    this.logger.log(`  Server Random: ${serverRandom.toString('hex')}`);

    const myCertificate = this.caClientService.getMyCertificate();
    
    if (!myCertificate) {
      throw new Error('No certificate available.  CA client not initialized.');
    }

    this.logger.log(`  Sending certificate:  ${myCertificate.serialNumber}`);

    const session: HandshakeSession = {
      clientRandom:  clientRandomBuffer,
      serverRandom: serverRandom,
      certificate: myCertificate,
    };
    this.sessions.set(fromNodeId, session);

    return {
      serverRandom: serverRandom.toString('base64'),
      certificate:  myCertificate,
    };
  }

  async handleEncryptedPremaster(fromNodeId: string, encryptedPremaster: string) {
    this.logger.log(`\n=== HANDLING ENCRYPTED PREMASTER from ${fromNodeId} ===`);

    const session = this.sessions.get(fromNodeId);
    if (!session) {
      throw new Error('No handshake session found');
    }

    const encryptedBuffer = Buffer.from(encryptedPremaster, 'base64');
    this.logger.log(`  Encrypted size: ${encryptedBuffer.length} bytes`);

    const myPrivateKey = this.caClientService.getMyPrivateKey();
    
    if (!myPrivateKey) {
      throw new Error('No private key available');
    }

    this.logger.log('  Decrypting with private key (RSA-OAEP-SHA256)...');

    const premasterSecret = privateDecrypt(
      {
        key: myPrivateKey,
        padding: 1,
        oaepHash: 'sha256',
      },
      encryptedBuffer
    );

    session.premasterSecret = premasterSecret;
    this.logger.log(`  Premaster Secret: ${premasterSecret.toString('hex')}`);

    this.logger.log('\n  Deriving session keys (HKDF-SHA256)...');
    const sessionKeys = this. deriveSessionKeys(
      session.premasterSecret,
      session.clientRandom,
      session.serverRandom
    );
    session.sessionKeys = sessionKeys;

    this.logger.log('  ✓ Session keys derived');

    const finishedMessage = this.encryptFinishedMessage(sessionKeys, 'server finished', 0);

    return finishedMessage;
  }

  async handleFinished(fromNodeId: string, finishedData: any) {
    this.logger.log(`\n=== HANDLING FINISHED MESSAGE from ${fromNodeId} ===`);

    const session = this.sessions. get(fromNodeId);
    if (!session || !session.sessionKeys) {
      throw new Error('No session keys available');
    }

    const ciphertext = Buffer.from(finishedData.ciphertext, 'base64');
    const iv = Buffer.from(finishedData.iv, 'base64');
    const authTag = Buffer.from(finishedData.authTag, 'base64');

    this.logger.log(`  Ciphertext: ${ciphertext. toString('hex')}`);
    this.logger.log(`  IV: ${iv.toString('hex')}`);

    const decipher = createDecipheriv('aes-256-gcm', session.sessionKeys.encryptionKey, iv);
    decipher.setAuthTag(authTag);

    let plaintext = decipher.update(ciphertext);
    plaintext = Buffer.concat([plaintext, decipher.final()]);

    const message = plaintext.toString('utf8');
    this.logger.log(`  Decrypted message: "${message}"`);

    const expectedMessage = finishedData.sequenceNumber === 0 ? 'server finished' : 'client finished';

    if (message !== expectedMessage) {
      throw new Error('Finished message verification failed');
    }

    this.logger.log('  ✓ Finished message verified');
    this.logger.log('\n=== HANDSHAKE COMPLETE ===');

    return {
      success: true,
      message: 'Handshake completed',
    };
  }

  private deriveSessionKeys(
    premasterSecret: Buffer,
    clientRandom: Buffer,
    serverRandom: Buffer
  ): SessionKeys {
    const seed = Buffer.concat([clientRandom, serverRandom]);
  
    // hkdfSync returns ArrayBuffer, convert to Buffer
    const keyMaterialArrayBuffer = hkdfSync(
      'sha256',
      premasterSecret,
      seed,
      Buffer.from('TLS 1.2 key expansion'),
      80
    );
  
    // Convert ArrayBuffer to Buffer
    const keyMaterial = Buffer.from(keyMaterialArrayBuffer);
  
    return {
      encryptionKey: keyMaterial. subarray(0, 32),   // Now this works
      ivSeed: keyMaterial.subarray(32, 48),
      hmacKey: keyMaterial.subarray(48, 80),
    };
  }

  private encryptFinishedMessage(sessionKeys: SessionKeys, message: string, sequenceNumber: number) {
    const iv = Buffer.alloc(16);
    sessionKeys.ivSeed.copy(iv);
    iv.writeUInt32BE(sequenceNumber, 12);

    const cipher = createCipheriv('aes-256-gcm', sessionKeys.encryptionKey, iv);

    let ciphertext = cipher.update(message, 'utf8');
    ciphertext = Buffer. concat([ciphertext, cipher. final()]);

    const authTag = cipher.getAuthTag();

    this.logger.log(`  Message: "${message}"`);
    this.logger.log(`  Ciphertext: ${ciphertext. toString('hex')}`);
    this.logger.log(`  Auth Tag: ${authTag.toString('hex')}`);

    return {
      ciphertext:  ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      sequenceNumber,
    };
  }

  getSession(nodeId: string): HandshakeSession | undefined {
    return this. sessions.get(nodeId);
  }

  getSessionKeys(nodeId: string): SessionKeys | undefined {
    return this.sessions.get(nodeId)?.sessionKeys;
  }
}
