import { Injectable, Inject, Logger } from "@nestjs/common";
import { HttpService } from "@nestjs/axios";
import { firstValueFrom } from "rxjs";
import { TopologyService } from "./topology.service";

@Injectable()
export class RoutingService {
  private readonly logger = new Logger("RoutingService");
  private visitedNodes: Set<string> = new Set();

  constructor(
    @Inject("NODE_ID") private readonly nodeId: string,
    private readonly topologyService: TopologyService,
    private readonly httpService: HttpService
  ) {}

  async broadcast(message: string) {
    this.logger.log(`\n=== BROADCASTING from ${this.nodeId} ===`);
    this.logger.log(`  Message: "${message}"`);

    const visited = [this.nodeId];
    await this.broadcastRecursive(message, visited);

    this.logger.log("  ✓ Broadcast complete");
  }

  private async broadcastRecursive(message: string, visited: string[]) {
    const neighbors = this.topologyService.getNeighbors(this.nodeId);

    for (const neighbor of neighbors) {
      if (!visited.includes(neighbor)) {
        visited.push(neighbor);

        this.logger.log(`  Forwarding to ${neighbor}...`);

        try {
          const url = this.topologyService.getNodeUrl(neighbor);
          await firstValueFrom(
            this.httpService.post(`${url}/network/receive-broadcast`, {
              message,
              visited,
              fromNodeId: this.nodeId,
            })
          );
        } catch (error) {
          this.logger.error(
            `  ✗ Failed to forward to ${neighbor}:  ${error.message}`
          );
        }
      }
    }
  }

  async receiveBroadcast(message: string, visited: string[]) {
    this.logger.log(`\n=== RECEIVED BROADCAST at ${this.nodeId} ===`);
    this.logger.log(`  Message: "${message}"`);
    this.logger.log(`  Path: ${visited.join(" -> ")}`);

    // Continue forwarding to neighbors not in visited list
    await this.broadcastRecursive(message, visited);
  }

  async routeMessage(toNodeId: string, message: string, path?: string[]) {
    this.logger.log(
      `\n=== ROUTING MESSAGE:  ${this.nodeId} -> ${toNodeId} ===`
    );

    if (toNodeId === this.nodeId) {
      this.logger.log("  Message reached destination");
      return;
    }

    // Simple routing: check if direct neighbor
    const neighbors = this.topologyService.getNeighbors(this.nodeId);

    if (neighbors.includes(toNodeId)) {
      this.logger.log(`  Direct route to ${toNodeId}`);
      const url = this.topologyService.getNodeUrl(toNodeId);
      await firstValueFrom(
        this.httpService.post(`${url}/network/receive-routed`, {
          message,
          fromNodeId: this.nodeId,
          toNodeId,
        })
      );
    } else {
      // Forward to first neighbor
      const nextHop = neighbors[0];
      if (nextHop) {
        this.logger.log(`  Forwarding via ${nextHop}`);
        const url = this.topologyService.getNodeUrl(nextHop);
        await firstValueFrom(
          this.httpService.post(`${url}/network/route`, {
            message,
            toNodeId,
            path: [...(path || []), this.nodeId],
          })
        );
      }
    }
  }
}
