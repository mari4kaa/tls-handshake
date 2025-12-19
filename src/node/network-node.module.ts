import { Module, Logger } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ConfigModule } from '@nestjs/config';
import { CaClientService, CaConfig } from '../ca-server/services/ca-client.service';

// Import your existing modules
import { CryptoModule } from '../crypto/crypto.module';
import { TransportModule } from '../transport/transport.module';
import { RoutingModule } from '../routing/routing.module';
import { SecureChannelModule } from '../secure-channel/secure-channel.module';
import { HandshakeModule } from '../handshake/handshake.module';
import { NetworkNodeController } from './network-node.controller';

@Module({
  imports: [
    ConfigModule. forRoot(),
    HttpModule,
    CryptoModule,
    TransportModule,
    RoutingModule,
    SecureChannelModule,
    HandshakeModule,
  ],
  controllers: [NetworkNodeController],
  providers: [
    {
      provide: 'NODE_ID',
      useFactory: () => {
        return process.env.NODE_ID || 'node1';
      },
    },
    {
      provide: 'NODE_PORT',
      useFactory: () => {
        return parseInt(process.env.NODE_PORT || '3000', 10);
      },
    },
    {
      provide:  'CA_CONFIG',
      useFactory: (): CaConfig => {
        return {
          authorityUrl: process.env.CA_URL || 'http://localhost:9000',
          retryAttempts: parseInt(process.env.CA_RETRY_ATTEMPTS || '30', 10),
          retryDelay: parseInt(process.env. CA_RETRY_DELAY || '2000', 10),
          certificateValidityDays: 365,
        };
      },
    },
    {
      provide: Logger,
      useValue: new Logger('NetworkNode'),
    },
    CaClientService,
  ],
  exports: ['NODE_ID', 'NODE_PORT', 'CA_CONFIG', CaClientService],
})
export class NetworkNodeModule {}