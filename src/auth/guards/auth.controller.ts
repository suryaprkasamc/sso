import { AuthService } from '../auth.service';
import { ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { loginDto } from '../auth.dto';
import { Controller, Post, Body } from '@nestjs/common';

@ApiTags('login')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @ApiOperation({ summary: 'Login' })
  @ApiBody({ type: loginDto })
  login(@Body() LoginDto: loginDto) {
    return this.authService.login(LoginDto);
  }
}
