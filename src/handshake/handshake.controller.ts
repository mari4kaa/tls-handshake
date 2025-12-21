import { Controller, Post, Body, Logger } from "@nestjs/common";
import { HandshakeService } from "./handshake.service";

@Controller("handshake")
export class HandshakeController {
  private readonly logger = new Logger("HandshakeTestController");

  constructor(private readonly handshakeService: HandshakeService) {}

  @Post("client-hello")
  async handleClientHello(
    @Body() body: { nodeId: string; clientRandom: string }
  ) {
    return await this.handshakeService.handleClientHello(
      body.nodeId,
      body.clientRandom
    );
  }

  @Post("encrypted-premaster")
  async handleEncryptedPremaster(
    @Body() body: { nodeId: string; encryptedPremaster: string }
  ) {
    return await this.handshakeService.handleEncryptedPremaster(
      body.nodeId,
      body.encryptedPremaster
    );
  }

  @Post("finished")
  async handleFinished(@Body() body: any) {
    return await this.handshakeService.handleFinished(body.nodeId, body);
  }

  @Post("test-initiate-handshake")
  async initiateHandshake(
    @Body() body: { targetNodeId: string; targetUrl: string }
  ) {
    this.logger.log(
      `Received handshake initiation request for ${body.targetNodeId}`
    );

    try {
      const result = await this.handshakeService.initiateHandshake(
        body.targetNodeId,
        body.targetUrl
      );

      this.logger.log(
        `✓ Handshake completed successfully with ${body.targetNodeId}`
      );

      return {
        success: true,
        message: `Handshake completed with ${body.targetNodeId}`,
        targetNodeId: body.targetNodeId,
      };
    } catch (error) {
      this.logger.error(
        `✗ Handshake failed with ${body.targetNodeId}:  ${error.message}`
      );

      return {
        success: false,
        error: error.message,
      };
    }
  }
}
