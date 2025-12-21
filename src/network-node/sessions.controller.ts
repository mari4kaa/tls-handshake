import { Controller, Get } from "@nestjs/common";
import { SecureChannelService } from "../secure-channel/secure-channel.service";

@Controller("sessions")
export class SessionsController {
  constructor(private readonly secureChannelService: SecureChannelService) {}

  @Get()
  getSessions() {
    const sessions = this.secureChannelService.getActiveSessions();

    return {
      sessions,
      total: sessions.length,
    };
  }
}
