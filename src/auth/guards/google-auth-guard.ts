import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {
  // Example: Add logging in your GoogleAuthGuard
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const activate = (await super.canActivate(context)) as boolean;
    const request = context.switchToHttp().getRequest();

    // Check if the user is already authenticated
    if (request.isAuthenticated()) {
      return true;
    }

    // If not authenticated, proceed with Google authentication
    await super.logIn(request);
    return activate;
  }
}
