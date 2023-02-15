import { UseGuards } from '@nestjs/common';
import {
  Args,
  Context,
  Info,
  Mutation,
  Query,
  Resolver,
} from '@nestjs/graphql';
import { GraphQLResolveInfo } from 'graphql';
import { SessionUser } from '../../../shared/decorators/user.decorator';
import { Params } from '../../../shared/dtos/params.utils';
import { AuthGuard } from '../../../shared/guards/auth.guard';
import { SessionGuard } from '../../../shared/guards/session.guard';
import { extractGraphRelations } from '../../../shared/helpers/relations.helper';
import { sanitizeRequest } from '../../../shared/helpers/sanitize.request';
import { sanitizeResponse } from '../../../shared/helpers/sanitize.response';
import {
  Login,
  Logout,
  UpdatePassword,
  UserData,
  UserInput,
  UserUpdate,
} from '../dtos/user.dto';
import { User } from '../entities/user.entity';
import { UserService } from '../services/user.service';

@Resolver()
export class UserResolver {
  constructor(private service: UserService) {}

  @UseGuards(SessionGuard)
  @Query(() => [User])
  async getUsers(
    @Args('params') params: Params,
    @Info() info: GraphQLResolveInfo,
  ): Promise<UserData[]> {
    return await this.service.findAll(
      params,
      [...extractGraphRelations({ entity: User, info })],
      {
        table: 'user',
        column: 'user.id',
        query:
          '(user.name ILIKE :search OR user.username ILIKE :search OR user.email ILIKE :search)',
        params: { ...params, search: `%${params.search}%` },
      },
    );
  }

  @Mutation(() => User)
  async register(
    @Args('user') user: UserInput,
    @Info() info: GraphQLResolveInfo,
  ): Promise<UserInput> {
    return await this.service.create(sanitizeRequest({ ...user }), [
      ...extractGraphRelations({ entity: User, info }),
    ]);
  }

  @UseGuards(AuthGuard)
  @Query(() => User)
  async login(
    @Args('login') user: Login,
    @Info() info: any,
    @Context() context: any,
  ): Promise<UserInput> {
    return await this.service.findOne({
      id: context.req.session.user.id,
      relations: [...extractGraphRelations({ entity: User, info })],
    });
  }

  @UseGuards(SessionGuard)
  @Query(() => User)
  async me(
    @SessionUser()
    user: User,
    @Info() info: GraphQLResolveInfo,
  ): Promise<User> {
    return await this.service.findOne({
      id: user.id,
      relations: [...extractGraphRelations({ entity: User, info })],
    });
  }

  @UseGuards(SessionGuard)
  @Mutation(() => User)
  updateUser(
    @Args('user') user: UserUpdate,
    @SessionUser() current: User,
    @Info() info: GraphQLResolveInfo,
  ): Promise<User> {
    return this.service.update(current.id, sanitizeRequest({ ...user }), [
      ...extractGraphRelations({ entity: User, info }),
    ]);
  }

  @UseGuards(SessionGuard)
  @Mutation(() => Logout)
  logout(@Context() context: any): Logout {
    context.req.session.destroy();
    return { message: 'User logged out successfully' };
  }

  @UseGuards(SessionGuard)
  @Query(() => User)
  async getUser(
    @Args('id', { type: () => String }) id: string,
    @Info() info: GraphQLResolveInfo,
  ): Promise<User> {
    return sanitizeResponse(
      await this.service.findOne({
        id,
        relations: [...extractGraphRelations({ entity: User, info })],
      }),
    );
  }

  @UseGuards(SessionGuard)
  @Mutation(() => User)
  updatePassword(
    @Args('user') user: UpdatePassword,
    @Info() info: any,
    @SessionUser()
    sessionUser: User,
  ): Promise<UpdatePassword> {
    return this.service.updatePassword(sessionUser.id, { ...user }, [
      ...extractGraphRelations({ entity: User, info }),
    ]);
  }
}
