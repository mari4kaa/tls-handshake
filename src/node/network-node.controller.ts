import { Controller, Get, Post, Body, Param, Inject } from '@nestjs/common';
import { CaClientService } from '../ca-server/services/ca-client.service';

@Controller()
export class NetworkNodeController {
  constructor(
    @Inject('NODE_ID') private readonly nodeId: string,
    private readonly caClient: CaClientService,
  ) {}

  @Get('info')
  getInfo() {
    return {
      nodeId: this.nodeId,
      certificateObtained: !!this.caClient.getMyCertificate(),
      certificate: this.caClient.getMyCertificate(),
      hasCAPublicKey: !!this.caClient.getCAPublicKey(),
      status: 'operational',
      timestamp: new Date().toISOString(),
    };
  }

  @Get('certificate')
  getMyCertificate() {
    return {
      certificate: this.caClient.getMyCertificate(),
      publicKey: this.caClient.getMyPublicKey(),
    };
  }

  @Post('verify-certificate')
  async verifyCertificate(@Body() certificate: any) {
    const isValid = await this.caClient.verifyCertificate(certificate);
    
    return {
      valid: isValid,
      verifiedAt: new Date().toISOString(),
    };
  }
}