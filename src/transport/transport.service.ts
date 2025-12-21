import { Injectable, Logger } from "@nestjs/common";
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
  private readonly logger = new Logger("TransportService");

  fragmentMessage(
    source: string,
    destination: string,
    payload: Buffer,
    mtu: number,
    sequenceNumber: number
  ): NetworkPacket[] {
    const maxPayloadSize = mtu - this.ESTIMATED_HEADER_SIZE;

    if (payload.length <= maxPayloadSize) {
      this.logger.log("\n  TRANSPORT: No fragmentation needed");
      this.logger.log(`    Payload size: ${payload.length} bytes`);
      this.logger.log(`    MTU: ${mtu} bytes`);
      this.logger.log(`    Max payload:  ${maxPayloadSize} bytes`);

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

    this.logger.log("\n  TRANSPORT: Fragmentation required");
    this.logger.log(`    Total payload:  ${payload.length} bytes`);
    this.logger.log(`    MTU: ${mtu} bytes`);
    this.logger.log(`    Header overhead: ${this.ESTIMATED_HEADER_SIZE} bytes`);
    this.logger.log(`    Max payload per fragment: ${maxPayloadSize} bytes`);
    this.logger.log(`    Total fragments: ${totalFragments}`);
    this.logger.log(`    Fragment ID: ${fragmentId}`);

    for (let i = 0; i < totalFragments; i++) {
      const start = i * maxPayloadSize;
      const end = Math.min(start + maxPayloadSize, payload.length);
      const fragmentPayload = payload.slice(start, end);

      this.logger.log(`\n    Fragment ${i + 1}/${totalFragments}:`);
      this.logger.log(`      Offset: ${start}-${end} bytes`);
      this.logger.log(`      Size: ${fragmentPayload.length} bytes`);
      this.logger.log(
        `      Data (hex): ${fragmentPayload
          .toString("hex")}`
      );

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

    this.logger.log(`\n  ✓ Created ${totalFragments} fragments`);

    return fragments;
  }

  reassembleFragments(packet: NetworkPacket): Buffer | null {
    if (!packet.isFragment) {
      this.logger.log("  TRANSPORT: Single packet, no reassembly needed");
      return packet.payload;
    }

    const key = packet.fragmentId!;

    if (!this.fragmentBuffer.has(key)) {
      this.fragmentBuffer.set(key, []);
      this.logger.log(`\n  TRANSPORT: Starting reassembly for ${key}`);
    }

    const fragments = this.fragmentBuffer.get(key)!;
    fragments.push({
      fragmentId: packet.fragmentId!,
      fragmentIndex: packet.fragmentIndex!,
      totalFragments: packet.totalFragments!,
      payload: packet.payload,
      timestamp: Date.now(),
    });

    this.logger.log(
      `  TRANSPORT: Received fragment ${packet.fragmentIndex! + 1}/${
        packet.totalFragments
      }`
    );
    this.logger.log(
      `    Fragments cached: ${fragments.length}/${packet.totalFragments}`
    );

    // Check if all fragments received
    if (fragments.length === packet.totalFragments) {
      // Sort by fragment index
      fragments.sort((a, b) => a.fragmentIndex - b.fragmentIndex);

      this.logger.log(`  TRANSPORT: All fragments received, reassembling...`);

      // Reassemble
      const reassembled = Buffer.concat(fragments.map((f) => f.payload));

      // Clean up
      this.fragmentBuffer.delete(key);

      this.logger.log(
        `  ✓ Reassembled ${reassembled.length} bytes from ${fragments.length} fragments`
      );
      this.logger.log(
        `  Reassembled data (hex): ${reassembled
          .toString("hex")}`
      );

      return reassembled;
    }

    this.logger.log(
      `  Waiting for ${
        packet.totalFragments! - fragments.length
      } more fragment(s)...`
    );

    // Clean up old fragments
    this.cleanupOldFragments();

    return null;
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
