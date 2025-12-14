import { Module } from '@nestjs/common';
import { NetworkNodeService } from './network-node.service';
import { NetworkNodeController } from './network-node.controller';
import { CryptoModule } from '../crypto/crypto.module';
import { HandshakeModule } from '../handshake/handshake.module';
import { TransportModule } from '../transport/transport.module';
import { RoutingModule } from '../routing/routing.module';
import { SecureChannelModule } from '../secure-channel/secure-channel.module';

@Module({
  imports: [
    CryptoModule,
    HandshakeModule,
    TransportModule,
    RoutingModule,
    SecureChannelModule,
  ],
  controllers: [NetworkNodeController],
  providers: [NetworkNodeService],
  exports: [NetworkNodeService],
})
export class NetworkNodeModule {}
