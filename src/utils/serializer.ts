import { PassportSerializer } from '@nestjs/passport';
import { Inject, Injectable } from '@nestjs/common';
import { AuthService } from 'src/auth/auth.service';

@Injectable()
export class SessionSerializer extends PassportSerializer {
  constructor(
    @Inject('AUTH_SERVICE') private readonly authService: AuthService,
  ) {
    super();
  }

  async serializeUser(
    user: any,
    done: (err: Error, user: any) => void,
  ): Promise<any> {
    console.log('serialize user ', user._json);
    await this.authService.saveUserId(user._json);
    done(null, user); // Store only the user id in the session
  }

  async deserializeUser(
    userId: any,
    done: (err: Error, user: any) => void,
  ): Promise<any> {
    console.log('deserialize user ');
    try {
      const user = await this.authService.findById(userId);
      return user ? done(null, user) : done(null, null);
    } catch (error) {
      return done(error, null);
    }
  }
}
