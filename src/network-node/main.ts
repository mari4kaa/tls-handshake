import { NestFactory } from '@nestjs/core';
import { NetworkNodeModule } from './network-node.module';
import { Logger } from '@nestjs/common';
import axios from 'axios';
import { CaClientService } from './ca-client.service';

async function bootstrapNetworkNode() {
  const nodeId = process.env.NODE_ID || 'node1';
  const nodePort = parseInt(process.env.NODE_PORT || '3000', 10);
  const caUrl = process.env.CA_URL || 'http://localhost:9000';
  
  const logger = new Logger('Bootstrap');
  
  console.log(`\n╔════════════════════════════════════════════════════════════╗`);
  console.log(`║     Network Node:  ${nodeId. padEnd(39)} ║`);
  console.log(`╚════════════════════════════════════════════════════════════╝\n`);
  
  const app = await NestFactory.create(NetworkNodeModule, {
    logger:  ['log', 'error', 'warn'],
  });
  
  app.enableCors({ 
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  });
  
  await app.listen(nodePort);
  
  logger.log(`✓ Node ${nodeId} HTTP server started on port ${nodePort}`);
  logger.log('');
  
  logger.log(`Connecting to Certificate Authority... `);
  logger.log(`  CA URL: ${caUrl}`);
  logger.log('');
  
  await waitForCA(caUrl, logger);
  
  const caClient = app.get(CaClientService);
  
  logger.log('Initializing CA client...');
  logger.log('');
  
  await caClient.initialize();
  
  logger.log('═══════════════════════════════════════════════════════════');
  logger.log(`✓ Node ${nodeId} is FULLY OPERATIONAL`);
  logger.log('═══════════════════════════════════════════════════════════');
  logger.log(`  HTTP Port: ${nodePort}`);
  logger.log(`  Certificate:  OBTAINED from CA`);
  logger.log(`  CA Public Key:  LOADED`);
  logger.log(`  Status: Ready for TLS handshakes`);
  logger.log('═══════════════════════════════════════════════════════════');
  logger.log('');
}

async function waitForCA(caUrl: string, logger: Logger): Promise<void> {
  const maxAttempts = 30;
  const delay = 2000;
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const response = await axios.get(`${caUrl}/health`, { timeout: 2000 });
      
      if (response.data.status === 'healthy') {
        logger.log('✓ Certificate Authority is available');
        logger.log(`  Status: ${response.data.status}`);
        logger.log(`  Role: ${response.data.role}`);
        logger.log('');
        return;
      }
    } catch (error) {
      logger.warn(`Waiting for CA...  (attempt ${attempt}/${maxAttempts})`);
      
      if (attempt < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  throw new Error('Certificate Authority not available');
}

bootstrapNetworkNode().catch(err => {
  console.error('❌ Failed to start Network Node:', err);
  process.exit(1);
});
