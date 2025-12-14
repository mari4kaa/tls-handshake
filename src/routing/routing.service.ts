import { Injectable } from '@nestjs/common';
import { NetworkTopology, NetworkLink, RouteInfo } from '../types';

@Injectable()
export class RoutingService {
  private topology: NetworkTopology = {
    nodes: [],
    links: [],
  };

  setTopology(topology: NetworkTopology): void {
    this.topology = topology;
  }

  addNode(nodeId: string): void {
    if (!this.topology.nodes.includes(nodeId)) {
      this.topology.nodes.push(nodeId);
    }
  }

  addLink(link: NetworkLink): void {
    this.topology.links.push(link);
  }

  getTopology(): NetworkTopology {
    return this.topology;
  }

  findRoute(source: string, destination: string): RouteInfo | null {
    if (source === destination) {
      return { path: [source], hops: 0 };
    }

    const visited = new Set<string>();
    const queue: { node: string; path: string[] }[] = [
      { node: source, path: [source] },
    ];

    visited.add(source);

    while (queue.length > 0) {
      const { node, path } = queue.shift()!;

      // Get neighbors
      const neighbors = this.getNeighbors(node);

      for (const neighbor of neighbors) {
        if (neighbor === destination) {
          const finalPath = [...path, neighbor];
          return { path: finalPath, hops: finalPath.length - 1 };
        }

        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push({ node: neighbor, path: [...path, neighbor] });
        }
      }
    }

    return null; // No route found
  }

  private getNeighbors(nodeId: string): string[] {
    const neighbors: string[] = [];

    for (const link of this.topology.links) {
      if (link.from === nodeId) {
        neighbors.push(link.to);
      }
      // If bidirectional, add reverse direction
      if (link.to === nodeId) {
        neighbors.push(link.from);
      }
    }

    return neighbors;
  }

  getLink(from: string, to: string): NetworkLink | null {
    return (
      this.topology.links.find(
        link =>
          (link.from === from && link.to === to) ||
          (link.from === to && link.to === from)
      ) || null
    );
  }

  getNextHop(currentNode: string, destination: string): string | null {
    const route = this.findRoute(currentNode, destination);
    if (!route || route.path.length < 2) {
      return null;
    }

    const currentIndex = route.path.indexOf(currentNode);
    if (currentIndex === -1 || currentIndex === route.path.length - 1) {
      return null;
    }

    return route.path[currentIndex + 1];
  }

  getAllNodes(): string[] {
    return [...this.topology.nodes];
  }

  buildSpanningTree(source: string): Map<string, string[]> {
    const tree = new Map<string, string[]>();
    const visited = new Set<string>();
    const queue: string[] = [source];

    visited.add(source);
    tree.set(source, []);

    while (queue.length > 0) {
      const node = queue.shift()!;
      const neighbors = this.getNeighbors(node);

      for (const neighbor of neighbors) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push(neighbor);

          if (!tree.has(node)) {
            tree.set(node, []);
          }
          tree.get(node)!.push(neighbor);
        }
      }
    }

    return tree;
  }

  getBroadcastTargets(
    currentNode: string,
    visitedNodes: string[]
  ): string[] {
    const neighbors = this.getNeighbors(currentNode);
    return neighbors.filter(neighbor => !visitedNodes.includes(neighbor));
  }
}
