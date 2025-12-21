import { Injectable, Inject, Logger } from "@nestjs/common";

@Injectable()
export class TopologyService {
  private readonly logger = new Logger("TopologyService");
  private topology: Map<string, string[]> = new Map();
  private nodeUrls: Map<string, string> = new Map();

  constructor(@Inject("NODE_ID") private readonly nodeId: string) {}

  configureTopology(topology: any) {
    this.logger.log(`\n=== CONFIGURING TOPOLOGY for ${this.nodeId} ===`);

    // Load topology
    Object.entries(topology).forEach(([node, neighbors]) => {
      this.topology.set(node, neighbors as string[]);
    });

    const defaultUrls = {
      node1: "http://localhost:3000",
      node2: "http://localhost:3001",
      node3: "http://localhost:3002",
      node4: "http://localhost:3003",
      node5: "http://localhost:3004",
    };

    Object.entries(defaultUrls).forEach(([node, url]) => {
      this.nodeUrls.set(node, url);
    });

    const neighbors = this.getNeighbors(this.nodeId);
    this.logger.log(`  Neighbors: ${neighbors.join(", ")}`);
    this.logger.log("  ✓ Topology configured");
  }

  getNeighbors(nodeId: string): string[] {
    return this.topology.get(nodeId) || [];
  }

  getNodeUrl(nodeId: string): string {
    return this.nodeUrls.get(nodeId) || `http://localhost:3000`;
  }

  getNetworkMap() {
    const map = {};
    this.topology.forEach((neighbors, node) => {
      map[node] = {
        neighbors,
        url: this.nodeUrls.get(node),
      };
    });
    return map;
  }
}
