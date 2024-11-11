import {
  Body,
  ConflictException,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import { RegisterAdminDto } from 'src/auth/dto/register-dto';
import { JwtStrategy } from 'src/auth/jwt.strategy';
import { AdminService } from './admin.service';
import { LoginDto } from 'src/auth/dto/login-dto';

@Controller('admin')
export class AdminController {
  constructor(
    private readonly adminService: AdminService,
    private jwtStrategy: JwtStrategy,
  ) {}

  @Post('registerAdmin')
  async createAdmin(@Body() registerAdminDto: RegisterAdminDto) {
    const token = await this.adminService.createAdmin(registerAdminDto);
    return {
      message: 'Admin Created Successfully',
      ...token,
    };
  }

  @HttpCode(HttpStatus.OK)
  @Post('login')
  async loginAdmin(@Body() loginDto: LoginDto) {
    const token = await this.adminService.login(loginDto);
    return {
      message: 'Login Successful',
      ...token,
    };
  }
}
