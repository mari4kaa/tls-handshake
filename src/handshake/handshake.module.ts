import { Module } from '@nestjs/common';
import { HandshakeService } from './handshake.service';
import { CryptoModule } from '../crypto/crypto.module';
import { CaModule } from '../ca/ca.module';

@Module({
  imports: [CryptoModule, CaModule],
  providers: [HandshakeService],
  exports: [HandshakeService],
})
export class HandshakeModule {}
