import {
  CanActivate,
  createParamDecorator,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { User } from '../../modules/user/entities/user.entity';
import { ErrorResponse } from '../interfaces/shared.interface';
@Injectable()
export class SessionGuard implements CanActivate {
  async canActivate(context: ExecutionContext) {
    const httpContext = GqlExecutionContext.create(context);
    const { req } = httpContext.getContext();
    try {
      if (req.session && req.session.user) {
        req.session.previousPath = req.path;
        return true;
      }
      if (req.headers?.authorization) {
        const buff = Buffer.from(
          req.headers?.authorization.replace('Basic ', ''),
          'base64',
        );
        const auth = buff.toString('ascii').split(':');
        const user = await User.verifyUser(auth[0], auth[1]);

        this.verifyUser(user);
        if (!req.session) {
          req.session = {};
        }
        req.session.user = user;
        return true;
      }
      throw new UnauthorizedException();
    } catch (e) {
      Logger.error(e.message);
      throw new UnauthorizedException();
    }
  }

  verifyUser = (user: any | ErrorResponse) => {
    if (user?.status) {
      throw new UnauthorizedException();
    }
    return;
  };
}
export const SessionUser = createParamDecorator((data, req) => {
  return req.session.passport.user;
});

@Injectable()
export class AuthenticatedGuard implements CanActivate {
  async canActivate(context: ExecutionContext) {
    const httpContext = GqlExecutionContext.create(context);
    const { req } = httpContext.getContext();
    return req.isAuthenticated();
  }
}
