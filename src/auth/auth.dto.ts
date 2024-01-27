import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString } from 'class-validator';

export class loginDto {
  @ApiProperty({ description: 'email', example: 'abc@gmail.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ description: '', example: 'passwd' })
  @IsString()
  password: string;
}

export class signupDto {
  //   @IsUUID()
  //   uuid: string;
  @IsEmail()
  email: string;
  @IsString()
  password: string;
}
export class logoutDto {
  @ApiProperty({ description: 'email', example: 'abc@gmail.com' })
  @IsEmail()
  email: string;
}
