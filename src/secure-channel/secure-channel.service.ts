import { Injectable } from '@nestjs/common';
import { CryptoService } from '../crypto/crypto.service';
import { SecureMessage, SessionKeys } from '../types';

@Injectable()
export class SecureChannelService {
  private sequenceNumbers: Map<string, number> = new Map();

  constructor(private cryptoService: CryptoService) {}

  encryptMessage(
    message: Buffer,
    sessionKeys: SessionKeys,
    channelId: string
  ): SecureMessage {
    console.log('\n=== SECURE CHANNEL: Encrypting Message (AES-256-GCM) ===');
    const sequenceNumber = this.getNextSequenceNumber(channelId);
    console.log('Message Encryption:');
    console.log(`  - Channel ID: ${channelId}`);
    console.log(`  - Sequence Number: ${sequenceNumber}`);
    console.log(`  - Plaintext length: ${message.length} bytes`);
    console.log(`  - Plaintext (first 100 bytes): ${message.toString('utf8', 0, Math.min(100, message.length))}`);
    
    const iv = this.cryptoService.generateIV(sessionKeys.ivSeed, sequenceNumber);
    console.log(`  - Generated IV (hex): ${iv.toString('hex')}`);
    console.log(`  - IV Seed (hex): ${sessionKeys.ivSeed.toString('hex')}`);
    console.log(`  - Encryption Key: ${sessionKeys.encryptionKey.toString('hex')}`);
    
    const { ciphertext, authTag } = this.cryptoService.aesEncrypt(
      message,
      sessionKeys.encryptionKey,
      iv
    );

    console.log('\nEncryption Result:');
    console.log(`  - Ciphertext length: ${ciphertext.length} bytes`);
    console.log(`  - Ciphertext: ${ciphertext.toString('hex')}`);
    console.log(`  - Auth Tag (hex): ${authTag.toString('hex')}`);
    console.log(`  - Algorithm: AES-256-GCM with authenticated encryption`);

    return {
      sequenceNumber,
      iv,
      ciphertext,
      authTag,
    };
  }

  decryptMessage(
    secureMessage: SecureMessage,
    sessionKeys: SessionKeys
  ): Buffer {
    console.log('\n=== SECURE CHANNEL: Decrypting Message (AES-256-GCM) ===');
    console.log('Message Decryption:');
    console.log(`  - Sequence Number: ${secureMessage.sequenceNumber}`);
    console.log(`  - Ciphertext length: ${secureMessage.ciphertext.length} bytes`);
    console.log(`  - Ciphertext: ${secureMessage.ciphertext.toString('hex')}`);
    console.log(`  - IV (hex): ${secureMessage.iv.toString('hex')}`);
    console.log(`  - Auth Tag (hex): ${secureMessage.authTag.toString('hex')}`);
    console.log(`  - Decryption Key: ${sessionKeys.encryptionKey.toString('hex')}`);
    
    const decrypted = this.cryptoService.aesDecrypt(
      secureMessage.ciphertext,
      sessionKeys.encryptionKey,
      secureMessage.iv,
      secureMessage.authTag
    );

    console.log('\nDecryption Result:');
    console.log(`  - Plaintext length: ${decrypted.length} bytes`);
    console.log(`  - Plaintext: ${decrypted.toString('utf8', 0, Math.min(200, decrypted.length))}`);
    
    return decrypted;
  }

  private getNextSequenceNumber(channelId: string): number {
    const current = this.sequenceNumbers.get(channelId) || 0;
    const next = current + 1;
    this.sequenceNumbers.set(channelId, next);
    return next;
  }

  resetSequenceNumber(channelId: string): void {
    this.sequenceNumbers.set(channelId, 0);
  }

  validateSequenceNumber(
    channelId: string,
    receivedSequenceNumber: number
  ): boolean {
    const expected = (this.sequenceNumbers.get(channelId) || 0) + 1;
    
    // Allow some window for out-of-order delivery
    const SEQUENCE_WINDOW = 3;
    const isValid = receivedSequenceNumber >= expected - SEQUENCE_WINDOW && 
                    receivedSequenceNumber <= expected + SEQUENCE_WINDOW;
    
    if (isValid) {
      this.sequenceNumbers.set(channelId, Math.max(expected, receivedSequenceNumber));
    }
    
    return isValid;
  }
}
