import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';

@Injectable()
export class JwtPassportStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    @InjectRepository(User)
    public userRepository: Repository<User>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWTSECRET,
    });
  }
  async validate(data: { id: string }): Promise<User> {
    try {
      if (!data || !data.id) {
        throw new UnauthorizedException();
      }
      return await this.userRepository.findOne({ where: { id: data.id } });
    } catch (e) {
      throw new Error(e.message);
    }
  }
}

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(
    @InjectRepository(User)
    public userRepository: Repository<User>,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.REFRESH_TOKEN_SECRET,
      passReqToCallback: true,
    });
  }
  async validate(req: Request, data: { id: string }): Promise<any> {
    try {
      const refreshToken = req
        ?.get('authorization')
        ?.replace('Bearer', '')
        .trim();

      if (!refreshToken) throw new ForbiddenException();
      if (!data || !data?.id) {
        throw new UnauthorizedException();
      }
      return {
        ...(await this.userRepository.findOneOrFail({
          where: { id: data.id },
        })),
        refreshToken,
      };
    } catch (e) {
      throw new Error(e.message);
    }
  }
}
