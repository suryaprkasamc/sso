import {
  Controller,
  Post,
  Body,
  // UnauthorizedException,
  Get,
  UseGuards,
  Req,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { loginDto, logoutDto } from './auth.dto';
import { AuthGuard } from '@nestjs/passport';
// import { Request } from 'express';
import { GoogleAuthGuard } from './guards/google-auth-guard';
@ApiBearerAuth()
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/local/login')
  @ApiOperation({ summary: 'User Login' })
  @ApiResponse({ status: 200, description: 'Login successful' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async login(@Body() credentials: loginDto) {
    try {
      return await this.authService.login(credentials);
    } catch (error) {
      // Handle unauthorized access (incorrect credentials)
      return error;
    }
  }

  @Post('/local/signUp')
  @ApiOperation({ summary: 'user signup' })
  @ApiResponse({ status: 200, description: 'Login successful' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async signUp(@Body() credentials: loginDto) {
    try {
      const user = await this.authService.signUp(credentials);
      return {
        message: 'Account creation  successful',
        user,
      };
    } catch (error) {
      // Handle unauthorized access (incorrect credentials)
      return error;
    }
  }

  @UseGuards(AuthGuard('local'))
  @Post('/logout')
  @ApiOperation({ summary: 'user logout' })
  async logout(@Body() emailId: logoutDto) {
    return await this.authService.logout(emailId.email);
  }
  // @UseGuards(AuthGuard('local'))
  @UseGuards(GoogleAuthGuard)
  @Get('/check')
  @ApiOperation({ summary: 'checking the route ' })
  check() {
    // return await this.authService.logout(emailId.email);
    return 'guard function workign correctly ';
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Get('/refresh')
  @ApiOperation({ summary: 'refresh token ' })
  async refresh(@Req() req) {
    return await this.authService.refresh(req.user);
  }
  //   @UseGuards(AuthGuard('local'))
  @Get('/google/redirect/')
  @UseGuards(GoogleAuthGuard)
  @ApiOperation({ summary: 'google sso redirect' })
  async googleLoginRedirect(@Req() req, @Res() res) {
    try {
      // Extract relevant information from the req object
      const user = req.user._json; // Adjust this based on what you want to include in the response

      // Create a response object with only the necessary data
      const responseObject = {
        email: user.email,
        email_verified: user.email_verified,
        id: user.sub,
        name: user.name,
      };
      console.log(responseObject);

      res.status(200).json(responseObject);
    } catch (error) {
      // Handle errors
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  }

  @UseGuards(GoogleAuthGuard)
  @Get('/google/login/')
  @ApiOperation({ summary: 'google sso login  fads' })
  async googleLogin() {
    return 'google SSO login';
  }
}
