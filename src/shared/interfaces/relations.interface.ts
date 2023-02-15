import { GraphQLResolveInfo } from 'graphql';
import { EntitySchema, ObjectType } from 'typeorm';

export interface RelationParams {
  entity: string | ObjectType<unknown> | EntitySchema<unknown>;
  info: GraphQLResolveInfo;
}
