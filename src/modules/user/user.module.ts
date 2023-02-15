import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { UserResolver } from './resolvers/user.resolver';
import {
  JwtPassportStrategy,
  JwtRefreshStrategy,
} from './services/jwt.strategy.service';
import { UserService } from './services/user.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    JwtModule.register({}),
    PassportModule.register({}),
  ],
  providers: [
    UserService,
    UserResolver,
    JwtPassportStrategy,
    JwtRefreshStrategy,
  ],
  exports: [JwtPassportStrategy, PassportModule, JwtRefreshStrategy],
})
export class UserModule {}
