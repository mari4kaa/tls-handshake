import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { SecureChannelService } from './secure-channel.service';
import { SecureChannelController } from './secure-channel.controller';
import { HandshakeModule } from '../handshake/handshake.module';

@Module({
  imports: [HttpModule, HandshakeModule],
  providers: [SecureChannelService],
  controllers: [SecureChannelController],
  exports: [SecureChannelService],
})
export class SecureChannelModule {}
