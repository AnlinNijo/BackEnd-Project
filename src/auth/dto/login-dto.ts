import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class LoginDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsString()
  email: string;

  @IsString()
  @Length(6, 12)
  password: string;
}

export class loginDto {
  @IsEmail()
  @IsString()
  email: string;

  @IsString()
  @Length(6, 12)
  password: string;
}

export class RefreshTokenDto {
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}
