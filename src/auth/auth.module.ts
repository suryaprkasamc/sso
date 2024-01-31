import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { userLoginEntity } from './auth.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { AtStrategy, RtStrategy, GoogleStrategy } from './stategies';
import { PassportModule } from '@nestjs/passport';
import { SessionSerializer } from 'src/utils/serializer';
import { googleUserEntity } from './googleUser.entity';
import { TwitterStrategy } from './stategies/twitter.strategy';
@Module({
  imports: [
    TypeOrmModule.forFeature([userLoginEntity, googleUserEntity]),
    JwtModule.register({
      secret: process.env.jwt_secret || 'suryaisKing',
      signOptions: { expiresIn: process.env.jwt_expiry || '3600s' },
    }),
    PassportModule.register({ session: true }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    AtStrategy,
    RtStrategy,
    GoogleStrategy,
    TwitterStrategy,
    SessionSerializer,
    { provide: 'AUTH_SERVICE', useClass: AuthService },
  ],
})
export class AuthModule {}
