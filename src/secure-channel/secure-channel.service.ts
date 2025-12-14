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
    const sequenceNumber = this.getNextSequenceNumber(channelId);
    const iv = this.cryptoService.generateIV(sessionKeys.ivSeed, sequenceNumber);
    
    const { ciphertext, authTag } = this.cryptoService.aesEncrypt(
      message,
      sessionKeys.encryptionKey,
      iv
    );

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
    return this.cryptoService.aesDecrypt(
      secureMessage.ciphertext,
      sessionKeys.encryptionKey,
      secureMessage.iv,
      secureMessage.authTag
    );
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
    const isValid = receivedSequenceNumber >= expected - 10 && 
                    receivedSequenceNumber <= expected + 10;
    
    if (isValid) {
      this.sequenceNumbers.set(channelId, Math.max(expected, receivedSequenceNumber));
    }
    
    return isValid;
  }
}
