import {
  CanActivate,
  ExecutionContext,
  NotAcceptableException,
} from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { User } from '../../modules/user/entities/user.entity';

export class AuthGuard implements CanActivate {
  async canActivate(context: ExecutionContext) {
    const httpContext = GqlExecutionContext.create(context);
    const { req } = httpContext.getContext();

    // const req = httpContext.getreq();
    try {
      if (req.body.username === '' || req.body.password === '') {
        throw new NotAcceptableException(
          `You provided an empty ${
            req.body.username === '' ? ' username' : 'password'
          }`,
        );
      }
      const user = await User.verifyUser(
        req.body.variables.login.email,
        req.body.variables.login.password,
      );
      return this.validateUser(user, req);
    } catch (e) {
      throw new NotAcceptableException(e.message);
    }
  }

  validateUser = (user: User, req: any) => {
    if (!user) {
      throw new NotAcceptableException(`Invalid Username or Password`);
    }
    if (!user) {
      throw new NotAcceptableException('You are not permitted to login');
    }
    if (!req.session) {
      req.session = {};
    }
    req.session.user = user;
    const sessionTime = 900000;
    req.session.cookie.expires = new Date(Date.now() + sessionTime);
    return true;
  };
}
