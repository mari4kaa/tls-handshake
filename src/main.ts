import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { NetworkNodeService } from './node/network-node.service';
import { RoutingService } from './routing/routing.service';

async function bootstrap() {
  const nodeId = process.env.NODE_ID || 'node1';
  const port = parseInt(process.env.NODE_PORT || '3000');

  const app = await NestFactory.create(AppModule);

  // Initialize network node
  const nodeService = app.get(NetworkNodeService);
  nodeService.initialize(nodeId, port);

  await app.listen(port);
  console.log(`Network node '${nodeId}' is listening on port ${port}`);
}

bootstrap();
