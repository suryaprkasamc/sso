import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {
  // Example: Add logging in your GoogleAuthGuard
  async canActivate(context: ExecutionContext): Promise<boolean> {
    console.log('%%%%%%%%%%%%%%%%%%%%%%%%%% checking the google guard  %%%%%%%%%%%%%%%%%%%%%%%%%');
    // return true;
    const activate = (await super.canActivate(context)) as boolean;
    const request = context.switchToHttp().getRequest();
    console.log('****************************************** authentication ******', request.isAuthenticated())

    // Check if the user is already authenticated
    if (request.isAuthenticated()) {
      console.log('User is already authenticated');
      return true;
    }

    // If not authenticated, proceed with Google authentication
    await super.logIn(request);

    console.log('User is not authenticated, redirecting to Google');
    return activate;
  }
}
