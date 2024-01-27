import {
  Injectable,
  NotFoundException,
  ConflictException,
  UnauthorizedException,
  ForbiddenException,
  UseGuards,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { userLoginEntity } from './auth.entity';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { AuthGuard } from '@nestjs/passport';
@Injectable()
export class AuthService {
  async refresh(user: any) {
    const { email, refreshToken } = user;

    console.log(email, refreshToken);

    try {
      const user = await this.userRepository.findOne({ where: { email } });
      if (!user) throw new NotFoundException('user not found');
      const isRtmatched = refreshToken === user.hashedRt;
      console.log({ isRtmatched });
      if (isRtmatched) {
        const data = await this.getTokens(user.email);
        user.hashedRt = data.refreshToken || 'token';
        await this.userRepository.save(user);
        return { token: data };
      } else {
        throw new ForbiddenException('Access denied');
      }
    } catch (error) {
      return error;
    }
  }
  constructor(
    @InjectRepository(userLoginEntity)
    private readonly userRepository: Repository<userLoginEntity>,
    private readonly jwtService: JwtService,
  ) {}
  saltRounds = 10; // Number of salt rounds to use during hashing
  async getTokens(email: string) {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        { sub: email, email },
        { expiresIn: 60 * 5, secret: 'at-surya' },
      ),
      this.jwtService.signAsync(
        { sub: email, email },
        { expiresIn: 60 * 5 * 25 * 7, secret: 'rt-surya' },
      ),
    ]);
    return { accessToken: at, refreshToken: rt };
  }

  async signUp(userInfo): Promise<string> {
    const { email, password } = userInfo;

    try {
      // Check if the user already exists
      const existingUser = await this.findUserByEmail(email);

      if (existingUser) {
        throw new ConflictException('Email already exists');
      }

      // If the email doesn't exist, add the user
      const hashedPassword = await this.hashPassword(password);
      const token = await this.getTokens(email);
      const newUser = this.userRepository.create({
        ...userInfo,
        password: hashedPassword,
        hashedRt: token.refreshToken,
      });
      await this.userRepository.save(newUser);

      return JSON.stringify({
        message: 'User registered successfully',
        user: userInfo.mail,
        token,
      });
    } catch (error) {
      throw new NotFoundException(`Failed to register user: ${error.message}`);
    }
  }

  async login(userInfo): Promise<any> {
    const { email, password = '' } = userInfo;

    // Check if the user already exists
    const user = await this.userRepository.findOne({ where: { email } });
    if (user) {
      const isValid = await this.validateUser(password, user.password);
      if (isValid) {
        try {
          const data = await this.getTokens(user.email);
          user.hashedRt = data.refreshToken || 'token';
          await this.userRepository.save(user);

          return {
            email: user.email,
            message: 'Login successful',
            data,
          };
        } catch (error) {
          console.error('Error generating access token:', error);
          throw new UnauthorizedException('Failed to generate access token');
        }
      } else throw new UnauthorizedException('not valid credentials');
    }
  }
  async logout(email: string) {
    console.log({ email });
    try {
      const user = await this.userRepository.findOne({
        where: { email },
      });
      console.log(user);
      if (!user) throw new NotFoundException('user not found');
      user.hashedRt = '';
      const nullRt = await this.userRepository.save(user);
      console.log({ nullRt });
      if (nullRt) return { message: 'User logged out successfully' };
      else throw new ForbiddenException('error logging out ');
    } catch (error) {
      return error;
    }
  }

  async validateUser(givenPassword, dbPassword) {
    return await this.comparePasswords(givenPassword, dbPassword);
  }

  async findUserByEmail(email: string): Promise<userLoginEntity | undefined> {
    return await this.userRepository.findOne({ where: { email } });
  }
  async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(this.saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
  }
  private async comparePasswords(
    plainTextPassword: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return await bcrypt.compare(plainTextPassword, hashedPassword);
  }
  async validateUserStrategy(email, password) {
    try {
      const user = await this.userRepository.findOne({ where: { email } });
      if (user) {
        const isValid = await this.validateUser(password, user.password);
        console.log({ isValid });
        if (isValid) {
          return true;
        }
        return false;
      }
    } catch (error) {
      return false;
    }
  }
}
