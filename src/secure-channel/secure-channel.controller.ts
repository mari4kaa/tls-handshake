import { Controller, Post, Get, Body, Param } from "@nestjs/common";
import { SecureChannelService, Message } from "./secure-channel.service";

@Controller("secure")
export class SecureChannelController {
  constructor(private readonly secureChannelService: SecureChannelService) {}

  @Post("send")
  async sendSecureMessage(@Body() body: { toNodeId: string; message: string }) {
    try {
      const result = await this.secureChannelService.sendSecureMessage(
        body.toNodeId,
        body.message
      );

      return {
        success: true,
        sequenceNumber: result.sequenceNumber,
        toNodeId: body.toNodeId,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  @Get("messages/:fromNode")
  getMessages(@Param("fromNode") fromNode: string) {
    const messages = this.secureChannelService.getMessages(fromNode);

    return {
      messages,
      total: messages.length,
      fromNode,
    };
  }

  @Post("messages/:fromNode/clear")
  clearMessages(@Param("fromNode") fromNode: string) {
    this.secureChannelService.clearMessages(fromNode);

    return {
      success: true,
      message: `Messages from ${fromNode} cleared`,
    };
  }

  @Post("receive-packet")
  async receivePacket(@Body() packet: any) {
    try {
      const result = await this.secureChannelService.receivePacket(packet);

      return {
        success: true,
        ...result,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }
}
