import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { userLoginEntity } from './auth.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { LocalStrategy } from './stategies/strategy.local';
import { AtStrategy, RtStrategy } from './stategies';
@Module({
  imports: [
    TypeOrmModule.forFeature([userLoginEntity]),
    JwtModule.register({
      secret: process.env.jwt_secret || 'suryaisKing',
      signOptions: { expiresIn: process.env.jwt_expiry || '3600s' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, AtStrategy, RtStrategy],
})
export class AuthModule {}
