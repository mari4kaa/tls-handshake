import { Module, Global } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { RoutingService } from './routing.service';
import { TopologyService } from './topology.service';

@Global()
@Module({
  imports: [HttpModule],
  providers: [
    RoutingService,
    TopologyService,
  ],
  exports: [RoutingService, TopologyService],
})
export class RoutingModule {}
