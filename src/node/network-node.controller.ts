import { Controller, Post, Get, Body, Param } from '@nestjs/common';
import { NetworkNodeService } from './network-node.service';
import { deserializeBuffers } from '../utils';

@Controller()
export class NetworkNodeController {
  constructor(private nodeService: NetworkNodeService) {}

  @Get('info')
  getNodeInfo() {
    return {
      nodeId: this.nodeService.getNodeId(),
      publicKey: this.nodeService.getPublicKey(),
    };
  }

  @Post('handshake/client-hello')
  handleClientHello(@Body() body: any) {
    const deserialized = deserializeBuffers(body);
    const { fromNode, clientHello } = deserialized;
    const serverHello = this.nodeService.handleClientHello(
      fromNode,
      clientHello
    );
    return serverHello;
  }

  @Post('handshake/encrypted-premaster')
  handleEncryptedPremaster(@Body() body: any) {
    const deserialized = deserializeBuffers(body);
    const { fromNode, encryptedPremaster } = deserialized;
    const finished = this.nodeService.handleEncryptedPremaster(
      fromNode,
      encryptedPremaster
    );
    return finished;
  }

  @Post('handshake/finished')
  handleFinished(@Body() body: any) {
    const deserialized = deserializeBuffers(body);
    const { fromNode, finished } = deserialized;
    this.nodeService.handleFinishedMessage(fromNode, finished, false);
    return { success: true };
  }

  @Post('network/route')
  async handleRoute(@Body() body: any) {
    const deserialized = deserializeBuffers(body);
    const { packet } = deserialized;
    this.nodeService.handleIncomingPacket(packet);
    return { success: true };
  }

  @Post('network/broadcast')
  async handleBroadcast(@Body() body: any) {
    const deserialized = deserializeBuffers(body);
    const { fromNode, message, visitedNodes } = deserialized;
    // Get port from environment or use default
    const port = parseInt(process.env.NODE_PORT || '3000');
    await this.nodeService.handleBroadcast(
      fromNode,
      message,
      visitedNodes,
      port
    );
    return { success: true };
  }

  @Post('secure/send')
  async sendSecureMessage(@Body() body: any) {
    const { targetNode, message, targetPort } = body;
    await this.nodeService.sendSecureMessage(targetNode, message, targetPort);
    return { success: true };
  }

  @Get('secure/messages/:fromNode')
  getMessages(@Param('fromNode') fromNode: string) {
    const messages = this.nodeService.getMessages(fromNode);
    return { messages };
  }

  @Post('secure/messages/:fromNode/clear')
  clearMessages(@Param('fromNode') fromNode: string) {
    this.nodeService.clearMessages(fromNode);
    return { success: true };
  }

  @Get('sessions')
  getSessions() {
    const sessions = this.nodeService.getPeerSessions();
    const sessionData = Array.from(sessions.entries()).map(([peer, session]) => ({
      peer,
      isHandshakeComplete: session.isHandshakeComplete,
      hasSessionKeys: !!session.sessionKeys,
    }));
    return { sessions: sessionData };
  }
}
