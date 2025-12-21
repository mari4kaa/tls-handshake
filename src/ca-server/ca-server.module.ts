import { Module, Logger } from "@nestjs/common";
import { CaAuthorityService } from "./services/ca-authority.service";
import { CaController } from "./controllers/ca.controller";

@Module({
  controllers: [CaController],
  providers: [
    CaAuthorityService,
    {
      provide: Logger,
      useValue: new Logger("CAServer"),
    },
  ],
  exports: [CaAuthorityService],
})
export class CaServerModule {}
