import { Controller, Post, Body } from "@nestjs/common";
import { RoutingService } from "../routing/routing.service";

@Controller("network")
export class NetworkController {
  constructor(private readonly routingService: RoutingService) {}

  @Post("broadcast")
  async broadcast(@Body() body: { message: string }) {
    try {
      await this.routingService.broadcast(body.message);

      return {
        success: true,
        message: "Broadcast sent",
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  @Post("receive-broadcast")
  async receiveBroadcast(
    @Body() body: { message: string; visited: string[]; fromNodeId: string }
  ) {
    await this.routingService.receiveBroadcast(body.message, body.visited);
    return { success: true };
  }

  @Post("route")
  async routeMessage(
    @Body() body: { toNodeId: string; message: string; path?: string[] }
  ) {
    try {
      await this.routingService.routeMessage(
        body.toNodeId,
        body.message,
        body.path
      );

      return {
        success: true,
        message: `Message routed to ${body.toNodeId}`,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
      };
    }
  }

  @Post("receive-routed")
  async receiveRoutedMessage(
    @Body() body: { message: string; fromNodeId: string; toNodeId: string }
  ) {
    return { success: true, message: "Message received" };
  }
}
