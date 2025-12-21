import { Injectable } from "@nestjs/common";
import { NetworkPacket } from "../types";

export interface Fragment {
  fragmentId: string;
  fragmentIndex: number;
  totalFragments: number;
  payload: Buffer;
  timestamp: number;
}

@Injectable()
export class TransportService {
  private fragmentBuffer: Map<string, Fragment[]> = new Map();
  private readonly FRAGMENT_TIMEOUT = 30000; // 30 seconds
  private readonly ESTIMATED_HEADER_SIZE = 200;

  fragmentMessage(
    source: string,
    destination: string,
    payload: Buffer,
    mtu: number,
    sequenceNumber: number
  ): NetworkPacket[] {
    const maxPayloadSize = mtu - this.ESTIMATED_HEADER_SIZE;

    if (payload.length <= maxPayloadSize) {
      return [
        {
          source,
          destination,
          payload,
          sequenceNumber,
          isFragment: false,
        },
      ];
    }

    // Fragment the payload
    const fragments: NetworkPacket[] = [];
    const fragmentId = `${source}-${destination}-${Date.now()}`;
    const totalFragments = Math.ceil(payload.length / maxPayloadSize);

    for (let i = 0; i < totalFragments; i++) {
      const start = i * maxPayloadSize;
      const end = Math.min(start + maxPayloadSize, payload.length);
      const fragmentPayload = payload.slice(start, end);

      fragments.push({
        source,
        destination,
        payload: fragmentPayload,
        sequenceNumber: sequenceNumber + i,
        isFragment: true,
        fragmentId,
        fragmentIndex: i,
        totalFragments,
      });
    }

    return fragments;
  }

  reassembleFragments(packet: NetworkPacket): Buffer | null {
    if (!packet.isFragment) {
      return packet.payload;
    }

    const key = packet.fragmentId!;

    if (!this.fragmentBuffer.has(key)) {
      this.fragmentBuffer.set(key, []);
    }

    const fragments = this.fragmentBuffer.get(key)!;
    fragments.push({
      fragmentId: packet.fragmentId!,
      fragmentIndex: packet.fragmentIndex!,
      totalFragments: packet.totalFragments!,
      payload: packet.payload,
      timestamp: Date.now(),
    });

    // Check if all fragments received
    if (fragments.length === packet.totalFragments) {
      // Sort by fragment index
      fragments.sort((a, b) => a.fragmentIndex - b.fragmentIndex);

      // Reassemble
      const reassembled = Buffer.concat(fragments.map((f) => f.payload));

      // Clean up
      this.fragmentBuffer.delete(key);

      return reassembled;
    }

    // Clean up old fragments
    this.cleanupOldFragments();

    return null; // Not all fragments received yet
  }

  private cleanupOldFragments(): void {
    const now = Date.now();

    for (const [key, fragments] of this.fragmentBuffer.entries()) {
      if (
        fragments.length > 0 &&
        now - fragments[0].timestamp > this.FRAGMENT_TIMEOUT
      ) {
        this.fragmentBuffer.delete(key);
      }
    }
  }

  async applyDelay(delayMs: number): Promise<void> {
    if (delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  shouldDropPacket(lossRate: number): boolean {
    return Math.random() < lossRate;
  }

  estimatePacketSize(packet: NetworkPacket): number {
    return JSON.stringify(packet).length;
  }
}
