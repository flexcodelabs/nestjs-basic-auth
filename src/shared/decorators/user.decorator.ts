import { createParamDecorator } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';

export const SessionUser = createParamDecorator(
  (data, context) => GqlExecutionContext.create(context).getContext().req.user,
);
