import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { UsersService } from 'src/users/users.service';
import { LoginDto } from './dto/login-dto';
import * as bcrypt from 'bcrypt';
import { RegisterUserDto } from './dto/register-dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private jwtStrategy: JwtService,
    private readonly usersService: UsersService,
  ) {}

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;

    const user = await this.prisma.user.findUnique({
      where: { email },
    });
    if (!user) {
      throw new NotFoundException('Invalid Credentials');
    }

    const validatePassword = await bcrypt.compare(password, user.password);

    if (!validatePassword) {
      throw new NotFoundException('Invalid Password');
    }
    return this.generateToken(user.id, user.email, user.role);
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email } = registerUserDto;

    const existing = await this.usersService.findByEmail(email);

    if (existing) {
      throw new ConflictException('User Already Exist');
    }
    const user = await this.usersService.createUser(registerUserDto);
    return this.generateToken(user.id, user.email, user.role);
  }

  async generateToken(id: string, email: string, role: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }
    const payload = { sub: id, email, role };
    const accessToken = this.jwtStrategy.sign(payload, {
      expiresIn: process.env.JWT_EXPIRES_IN,
    });

    const refreshToken = this.jwtStrategy.sign(payload, {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
    });

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    await this.prisma.user.update({
      where: {
        id: id,
      },
      data: { refreshToken: hashedRefreshToken },
    });
    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshAccessToken(refreshToken: string) {
    try {
      const payload = await this.jwtStrategy.verify(refreshToken);
      const user = await this.prisma.user.findUnique({
        where: {
          id: payload.sub,
        },
      });
      if (!user || !(await bcrypt.compare(refreshToken, user.refreshToken))) {
        throw new UnauthorizedException('Invalid Refresh Token');
      }

      const newAccessToken = this.jwtStrategy.sign(
        { email: user.email, sub: user.id },
        { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN },
      );
      return { accessToken: newAccessToken };
    } catch (error) {
      throw new UnauthorizedException('Invalid Refresh Token');
    }
  }
}
