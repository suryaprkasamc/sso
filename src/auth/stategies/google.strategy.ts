// google.strategy.ts

import { PassportStrategy } from '@nestjs/passport';
import { Inject, Injectable } from '@nestjs/common';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { AuthService } from '../auth.service';
import * as dotenv from 'dotenv';
dotenv.config();
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    @Inject('AUTH_SERVICE') private readonly userService: AuthService,
    // private readonly userService: AuthService,
  ) {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      // passReqToCallback: true,
      scope: ['profile', 'email'],
    });
  }

  //   async validate(
  //     accessToken: string,
  //     refreshToken: string,
  //     profile: any,
  //     done: VerifyCallback,
  //   ): Promise<any> {
  //     const { email, name, picture } = profile._json;
  //     const user = {
  //       email,
  //       name,
  //       picture,
  //       accessToken,
  //       refreshToken,
  //     };
  //     console.log('calling auth service ');
  //     try {
  //       console.log(profile._json)
  //       const a = await this.userService.validateGoogle(profile._json);
  //       console.log('output',a)
  //       done(null, true);
  //     } catch (error) {
  //       done(error, false);
  //     }
  //   }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    console.log('*****************************************************',accessToken)
    done(null, profile);
  }
}
