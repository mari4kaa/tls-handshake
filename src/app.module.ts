import { Module } from '@nestjs/common';
import { CaModule } from './ca/ca.module';
import { CryptoModule } from './crypto/crypto.module';
import { HandshakeModule } from './handshake/handshake.module';
import { TransportModule } from './transport/transport.module';
import { RoutingModule } from './routing/routing.module';
import { SecureChannelModule } from './secure-channel/secure-channel.module';
import { NetworkNodeModule } from './node/network-node.module';

@Module({
  imports: [
    CaModule,
    CryptoModule,
    HandshakeModule,
    TransportModule,
    RoutingModule,
    SecureChannelModule,
    NetworkNodeModule,
  ],
})
export class AppModule {}
