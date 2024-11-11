import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterUserDto } from './dto/register-dto';
import { LoginDto, RefreshTokenDto } from './dto/login-dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    const tokens = await this.authService.login(loginDto);
    return {
      message: 'login successfull',
      ...tokens,
    };
  }

  @Post('registerUser')
  async newUser(@Body() registerUserDto: RegisterUserDto) {
    const tokens = await this.authService.registerUser(registerUserDto);
    return {
      message: 'User Registered Successfully',
      ...tokens,
    };
  }

  @Post('refresh-token')
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    const { refreshToken } = refreshTokenDto;
    const newAccessToken =
      await this.authService.refreshAccessToken(refreshToken);
    return {
      message: 'Token Generated Successfully',
      accessToken: newAccessToken,
    };
  }
}
