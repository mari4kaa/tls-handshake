import { Controller, Get, Post, Body } from '@nestjs/common';
import { CertificateAuthorityService } from './ca.service';

@Controller('ca')
export class CaController {
  constructor(private caService: CertificateAuthorityService) {}

  @Get('root-certificate')
  getRootCertificate() {
    return this.caService.getRootCertificate();
  }

  @Post('sign-certificate')
  signCertificate(@Body() body: { publicKey: string; subject: string }) {
    const certificate = this.caService.signServerCertificate(
      body.publicKey,
      body.subject
    );
    return { certificate };
  }

  @Post('verify-certificate')
  verifyCertificate(@Body() body: { certificate: string }) {
    const isValid = this.caService.verifyCertificate(body.certificate);
    return { valid: isValid };
  }

  @Get('issued-certificates')
  getIssuedCertificates() {
    return { certificates: this.caService.getIssuedCertificates() };
  }
}
