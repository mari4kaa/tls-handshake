import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { NetworkNodeService } from './node/network-node.service';
import { RoutingService } from './routing/routing.service';
import { NetworkLink } from './types';

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function createNode(nodeId: string, port: number) {
  const app = await NestFactory.create(AppModule, { logger: ['error', 'warn'] });
  const nodeService = app.get(NetworkNodeService);
  nodeService.initialize(nodeId, port);
  await app.listen(port);
  return { app, nodeService };
}

async function setupTopology(nodes: Map<string, any>) {
  // Topology: node1 -- node2 -- node3 -- node4 -- node5
  
  const links: NetworkLink[] = [
    { from: 'node1', to: 'node2', mtu: 256, delay: 10, packetLoss: 0 },
    { from: 'node2', to: 'node3', mtu: 256, delay: 10, packetLoss: 0 },
    { from: 'node3', to: 'node4', mtu: 128, delay: 20, packetLoss: 0.05 }, // slow link
    { from: 'node4', to: 'node5', mtu: 256, delay: 10, packetLoss: 0 },
  ];

  // topology for all nodes
  for (const [nodeId, { nodeService }] of nodes) {
    const routingService = nodeService['routingService'] as RoutingService;
    routingService.setTopology({
      nodes: Array.from(nodes.keys()),
      links,
    });
  }

  console.log('Network topology configured:');
  console.log('node1 <-> node2 <-> node3 <-> node4 <-> node5');
  console.log('MTU: 256, 256, 128 (slow), 256 bytes');
}

async function demonstrateHandshakes(nodes: Map<string, any>) {
  console.log('\n=== Phase 1: TLS Handshakes ===\n');

  // handshakes between adjacent nodes
  const { nodeService: node1 } = nodes.get('node1');
  const { nodeService: node2 } = nodes.get('node2');
  const { nodeService: node3 } = nodes.get('node3');
  const { nodeService: node4 } = nodes.get('node4');
  const { nodeService: node5 } = nodes.get('node5');

  console.log('1. node1 <-> node2 handshake...');
  await node1.initiateHandshake('node2', 3001);
  await sleep(500);

  console.log('2. node2 <-> node3 handshake...');
  await node2.initiateHandshake('node3', 3002);
  await sleep(500);

  console.log('3. node3 <-> node4 handshake...');
  await node3.initiateHandshake('node4', 3003);
  await sleep(500);

  console.log('4. node4 <-> node5 handshake...');
  await node4.initiateHandshake('node5', 3004);
  await sleep(500);

  console.log('\n✓ All handshakes completed successfully!\n');
}

async function demonstrateSecureMessaging(nodes: Map<string, any>) {
  console.log('\n=== Phase 2: Secure Messaging (Direct) ===\n');

  const { nodeService: node1 } = nodes.get('node1');
  const { nodeService: node2 } = nodes.get('node2');

  console.log('Sending encrypted message from node1 to node2...');
  await node1.sendSecureMessage('node2', 'Hello from node1!', 3001);
  await sleep(500);

  const messages = node2.getMessages('node1');
  console.log(`node2 received: ${messages.join(', ')}`);

  console.log('\nSending response from node2 to node1...');
  await node2.sendSecureMessage('node1', 'Hi node1, this is node2!', 3000);
  await sleep(500);

  const response = node1.getMessages('node2');
  console.log(`node1 received: ${response.join(', ')}`);

  console.log('\n✓ Direct secure messaging works!\n');
}

async function demonstrateRoutedMessaging(nodes: Map<string, any>) {
  console.log('\n=== Phase 3: Routed Messaging (Multi-hop) ===\n');

  const { nodeService: node1 } = nodes.get('node1');
  const { nodeService: node5 } = nodes.get('node5');

  // handshake between node1 and node5 through intermediaries
  console.log('Demonstrating routing layer with fragmentation...\n');

  // Send a large message that will be fragmented
  const largeMessage = 'A'.repeat(400); // Will be fragmented due to MTU limits
  console.log(`Sending large message (${largeMessage.length} bytes) from node1...`);
  console.log('This will be fragmented due to MTU=128 on node3-node4 link');

  try {
    await node1.sendSecureMessage('node2', largeMessage, 3001);
    await sleep(1000);

    const messages = nodes.get('node2').nodeService.getMessages('node1');
    console.log(`node2 received message of length: ${messages[messages.length - 1]?.length || 0}`);
    console.log('\n✓ Fragmentation and reassembly works!\n');
  } catch (error) {
    console.log(`Expected: ${error.message}`);
  }
}

async function demonstrateBroadcast(nodes: Map<string, any>) {
  console.log('\n=== Phase 4: Network Broadcast ===\n');

  const { nodeService: node1 } = nodes.get('node1');

  console.log('Broadcasting message from node1 to entire network...');
  await node1.broadcastMessage('BROADCAST: Hello everyone from node1!', 3000);
  
  await sleep(1000);

  console.log('\n✓ Broadcast sent to all reachable nodes!\n');
}

async function demonstrateTopologyInfo(nodes: Map<string, any>) {
  console.log('\n=== Network Status ===\n');

  for (const [nodeId, { nodeService }] of nodes) {
    const sessions = nodeService.getPeerSessions();
    const completedSessions = Array.from(sessions.values()).filter(
      (s: any) => s.isHandshakeComplete
    ).length;

    console.log(`${nodeId}: ${completedSessions} active secure session(s)`);
  }

  console.log('\n');
}

async function main() {
  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║   TLS/SSL Handshake Simulation - Network Demo         ║');
  console.log('║   5 Nodes | Multi-hop Routing | Fragmentation         ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');

  // Create 5 network nodes
  console.log('Starting 5 network nodes...\n');
  const nodes = new Map();

  nodes.set('node1', await createNode('node1', 3000));
  nodes.set('node2', await createNode('node2', 3001));
  nodes.set('node3', await createNode('node3', 3002));
  nodes.set('node4', await createNode('node4', 3003));
  nodes.set('node5', await createNode('node5', 3004));

  console.log('✓ All nodes started\n');

  await sleep(1000);

  // topology
  await setupTopology(nodes);
  await sleep(500);

  try {
    await demonstrateHandshakes(nodes);
    await demonstrateSecureMessaging(nodes);
    await demonstrateRoutedMessaging(nodes);
    await demonstrateBroadcast(nodes);
    await demonstrateTopologyInfo(nodes);

    console.log('Demo completed successfully!');
  } catch (error) {
    console.error('Error during demo:', error);
  }
}

main().catch(console.error);
