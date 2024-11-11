import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { RegisterAdminDto } from 'src/auth/dto/register-dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from 'src/auth/dto/login-dto';
import { strict } from 'assert';

@Injectable()
export class AdminService {
  constructor(
    private prisma: PrismaService,
    private jwtStrategy: JwtService,
  ) {}

  async createAdmin(registerAdminDto: RegisterAdminDto) {
    const { name, phoneNo, password, email } = registerAdminDto;
    const existing = await this.prisma.admin.findUnique({
      where: {
        email,
      },
    });
    if (existing) {
      throw new ConflictException('Admin Already Exist');
    }
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const admin = await this.prisma.admin.create({
      data: {
        email,
        name,
        phoneNo,
        password: hashedPassword,
      },
    });
    const payload = { email: admin.name, sub: admin.id };
    return this.token(admin.id, admin.email);
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const admin = await this.prisma.admin.findUnique({
      where: {
        email,
      },
    });
    if (!admin) throw new NotFoundException('Invalid Email');

    const valPassword = await bcrypt.compare(password, admin.password);
    if (!valPassword) {
      throw new NotFoundException('Wrong Password');
    }
    return this.token(admin.id, admin.email);
  }

  async token(id: string, email: string) {
    const admin = await this.prisma.admin.findUnique({
      where: {
        id,
      },
    });
    if (!admin) {
      throw new NotFoundException('Admin not found');
    }
    const payload = { sub: id, email };
    const accessToken = await this.jwtStrategy.sign(payload, {
      expiresIn: process.env.JWT_EXPIRES_IN,
    });

    const refreshToken = await this.jwtStrategy.sign(payload, {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
    });

    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    await this.prisma.admin.update({
      where: {
        id: id,
      },
      data: { refreshToken: hashedRefreshToken },
    });

    return { accessToken, refreshToken };
  }
}
