import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { AdminModule } from './admin/admin.module';
import { RolesModule } from './roles/roles.module';

@Module({
  imports: [UsersModule, PrismaModule, AuthModule, AdminModule, RolesModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
