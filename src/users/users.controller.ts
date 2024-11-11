import {
  Controller,
  Get,
  Param,
  ParseIntPipe,
  Request,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly userService: UsersService) {}

  @Get()
  async getusers() {
    const user = await this.userService.findAll();
    return {
      message: 'Users Fetched Successfully',
      data: user,
    };
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@Request() req) {
    const id = req.user.id;
    const profile = await this.userService.getProfileById(id);
    return {
      message: 'User Profile Fetched Successfully',
      data: profile,
    };
  }
}
