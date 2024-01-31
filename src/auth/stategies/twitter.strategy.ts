// twitter.strategy.ts
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-twitter';
import { Injectable } from '@nestjs/common';
import * as dotenv from 'dotenv';
dotenv.config();
@Injectable()
export class TwitterStrategy extends PassportStrategy(Strategy, 'twitter') {
  constructor() {
    super({
      consumerKey: process.env.TWITTER_API_KEY,
      consumerSecret: process.env.TWITTER_KEY_SECRET,
      callbackURL: 'http://localhost:3000/auth/home',
      includeEmail: true,
    });
  }

  async validate(
    token: string,
    tokenSecret: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    const { displayName, emails } = profile;
    const user = {
      displayName,
      email: emails ? emails[0].value : null,
      twitterId: profile.id,
      location: profile._json.location,
      picture: profile._json.profile_image_url_https,
    };
    console.log('**********************user details ', user);
    done(null, user);
  }
}
