import { Controller, Post, Body, Get } from '@nestjs/common';
import { TopologyService } from './topology.service';

@Controller('topology')
export class TopologyController {
  constructor(
    private readonly topologyService: TopologyService,
  ) {}

  @Post('configure')
  configureTopology(@Body() body?: any) {
    // Default linear topology
    const topology = body?. topology || {
      node1: ['node2'],
      node2: ['node1', 'node3'],
      node3: ['node2', 'node4'],
      node4: ['node3', 'node5'],
      node5: ['node4'],
    };

    this.topologyService.configureTopology(topology);

    return {
      success: true,
      message: 'Topology configured',
    };
  }

  @Get('info')
  getTopologyInfo() {
    return this.topologyService.getNetworkMap();
  }
}
