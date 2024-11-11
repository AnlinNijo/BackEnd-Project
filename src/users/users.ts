import { Injectable } from '@nestjs/common';

@Injectable()
export class Users {
  email: string;
  firstName: string;
  lastName: string;
  password: string;
}
