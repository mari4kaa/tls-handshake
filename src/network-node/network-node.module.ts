import { Module, Global } from "@nestjs/common";
import { HttpModule } from "@nestjs/axios";
import { ConfigModule } from "@nestjs/config";
import { Logger } from "@nestjs/common";
import { CaClientService } from "./ca-client.service";

// Controllers
import { NetworkNodeController } from "./network-node.controller";
import { HandshakeController } from "../handshake/handshake.controller";
import { TopologyController } from "../routing/topology.controller";
import { NetworkController } from "./network.controller";
import { SessionsController } from "./sessions.controller";

// Service modules
import { TransportModule } from "../transport/transport.module";
import { RoutingModule } from "../routing/routing.module";
import { SecureChannelModule } from "../secure-channel/secure-channel.module";
import { HandshakeModule } from "../handshake/handshake.module";

@Global()
@Module({
  imports: [
    ConfigModule.forRoot(),
    HttpModule,
    TransportModule,
    RoutingModule,
    SecureChannelModule,
    HandshakeModule,
  ],
  controllers: [
    NetworkNodeController,
    HandshakeController,
    TopologyController,
    NetworkController,
    SessionsController,
  ],
  providers: [
    {
      provide: "NODE_ID",
      useFactory: () => process.env.NODE_ID || "node1",
    },
    {
      provide: "NODE_PORT",
      useFactory: () => parseInt(process.env.NODE_PORT || "3000", 10),
    },
    {
      provide: "CA_CONFIG",
      useFactory: () => ({
        authorityUrl: process.env.CA_URL || "http://localhost:9000",
        retryAttempts: 30,
        retryDelay: 2000,
        certificateValidityDays: 365,
      }),
    },
    {
      provide: Logger,
      useValue: new Logger("NetworkNode"),
    },
    CaClientService,
  ],
  exports: ["NODE_ID", "NODE_PORT", "CA_CONFIG", CaClientService, Logger],
})
export class NetworkNodeModule {}
