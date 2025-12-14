import { Module } from '@nestjs/common';
import { SecureChannelService } from './secure-channel.service';
import { CryptoModule } from '../crypto/crypto.module';

@Module({
  imports: [CryptoModule],
  providers: [SecureChannelService],
  exports: [SecureChannelService],
})
export class SecureChannelModule {}
