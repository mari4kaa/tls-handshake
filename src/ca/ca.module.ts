import { Module } from '@nestjs/common';
import { CertificateAuthorityService } from './ca.service';
import { CaController } from './ca.controller';
import { CryptoModule } from '../crypto/crypto.module';

@Module({
  imports: [CryptoModule],
  controllers: [CaController],
  providers: [CertificateAuthorityService],
  exports: [CertificateAuthorityService],
})
export class CaModule {}
