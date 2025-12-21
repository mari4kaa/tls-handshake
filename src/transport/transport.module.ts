import { Global, Module } from '@nestjs/common';
import { TransportService } from './transport.service';

@Global()
@Module({
  providers: [TransportService],
  exports: [TransportService],
})
export class TransportModule {}
