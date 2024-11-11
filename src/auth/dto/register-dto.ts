import { Role } from '@prisma/client';
import {
  IsEmail,
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsString,
  Length,
} from 'class-validator';

export class RegisterUserDto {
  @IsEmail()
  @IsString()
  email: string;

  @IsString()
  @Length(6, 12)
  password: string;

  @IsString()
  @Length(3, 15)
  firstName: string;

  @IsString()
  @Length(3, 15)
  lastName: string;

  @IsEnum(Role, { message: 'Invalid Role Provided' })
  role?: Role;
}

export class RegisterAdminDto {
  @IsString()
  name: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  phoneNo: string;

  @IsEmail()
  @IsNotEmpty()
  email: string;
}
