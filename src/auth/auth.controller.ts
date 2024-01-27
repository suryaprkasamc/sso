import {
  Controller,
  Post,
  Body,
  UnauthorizedException,
  Get,
  UseGuards,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiBearerAuth, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { loginDto, logoutDto } from './auth.dto';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
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
  @UseGuards(AuthGuard('local'))
  @Get('/check')
  @ApiOperation({ summary: 'user logout' })
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
}
