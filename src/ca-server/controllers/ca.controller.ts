import { Controller, Get, Post, Body, Logger, HttpCode } from '@nestjs/common';
import { CaAuthorityService } from '../services/ca-authority.service';
import { CertificateSigningRequest, Certificate } from '../interfaces/ca.interfaces';

@Controller()
export class CaController {
  private readonly logger = new Logger('CaController');

  constructor(private readonly caService: CaAuthorityService) {}

  @Get('health')
  getHealth() {
    return {
      status: 'healthy',
      role: 'authority',
      service: 'Certificate Authority Server',
      timestamp: new Date().toISOString(),
      capabilities: [
        'Issue certificates',
        'Verify certificates',
        'Revoke certificates',
        'Maintain certificate registry',
      ],
    };
  }

  @Get('public-key')
  getPublicKey() {
    this.logger.log('→ Public key requested');
    
    return {
      publicKey: this. caService.getPublicKey(),
      issuer: 'CN=Root CA,O=TLS Simulation',
      algorithm: 'RSA-2048',
      usage: 'Certificate signature verification',
    };
  }

  @Post('sign-certificate')
  @HttpCode(200)
  async signCertificate(@Body() csr: CertificateSigningRequest) {
    this.logger.log(`→ Certificate signing request from:  ${csr.nodeId}`);
    
    const certificate = await this.caService. signCertificate(csr);
    
    this.logger.log(`✓ Certificate issued to ${csr.nodeId}`);
    
    return certificate;
  }

  @Post('verify-certificate')
  @HttpCode(200)
  async verifyCertificate(@Body() certificate: Certificate) {
    this.logger.log(`→ Certificate verification request:  ${certificate.serialNumber}`);
    
    const result = this.caService.verifyCertificate(certificate);
    
    return {
      valid: result.valid,
      reason: result.reason,
      certificate: result.valid ? certificate : null,
      verifiedAt: new Date().toISOString(),
    };
  }

  @Get('issued-certificates')
  getIssuedCertificates() {
    const certificates = this.caService.getIssuedCertificates();
    
    this.logger.log(`→ Certificate registry requested (${certificates.length} certificates)`);
    
    return {
      certificates,
      total:  certificates.length,
      retrievedAt: new Date().toISOString(),
    };
  }

  @Post('revoke-certificate')
  @HttpCode(200)
  revokeCertificate(
    @Body() body: { serialNumber: string; reason: string }
  ) {
    this.logger.log(`→ Certificate revocation request:  ${body.serialNumber}`);
    
    this.caService. revokeCertificate(body.serialNumber, body.reason);
    
    return {
      success: true,
      message: 'Certificate revoked',
      serialNumber: body.serialNumber,
      revokedAt: new Date().toISOString(),
    };
  }
}