import { Module } from "@nestjs/common";
import { HttpModule } from "@nestjs/axios";
import { HandshakeService } from "./handshake.service";
import { HandshakeController } from "./handshake.controller";

@Module({
  imports: [HttpModule],
  providers: [HandshakeService],
  controllers: [HandshakeController],
  exports: [HandshakeService],
})
export class HandshakeModule {}
