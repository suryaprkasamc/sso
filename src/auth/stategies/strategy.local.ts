import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(
    private authService: AuthService,
    private jwtService: JwtService,
  ) {
    super();
  }

  async validateUser(email: string, password: string) {
    const user = await this.authService.validateUserStrategy(email, password);
    if (user) {
      try {
        const payload = { username: email, sub: { name: email } };
        const accessToken = await this.jwtService.sign(payload);
        console.log('local strategy wokring');
        console.log({ accessToken });

        return {
          email: email,
          message: 'Login successful',
          accessToken,
        };
      } catch (error) {
        console.error('Error generating access token:', error);
        throw new UnauthorizedException('Failed to generate access token');
      }
    } else throw new UnauthorizedException('not valid credentials');
  }
}
