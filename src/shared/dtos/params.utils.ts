import { InputType, Field } from '@nestjs/graphql';

@InputType()
export class Params {
  @Field({
    nullable: true,
  })
  page: number;

  @Field({
    nullable: true,
  })
  pageSize: number;

  @Field({
    nullable: true,
  })
  search: string;

  @Field({
    nullable: true,
  })
  paging: boolean;

  @Field({
    nullable: true,
  })
  status: string;

  @Field({
    nullable: true,
  })
  property: string;

  @Field({
    nullable: true,
  })
  direction: 'asc' | 'desc' | 'ASC' | 'DESC';

  @Field({
    nullable: true,
  })
  id: string;

  @Field(() => [GenericFilter], { nullable: true })
  filters?: GenericFilter[];
}

@InputType()
export class GenericFilter {
  @Field()
  key: string;

  @Field()
  value: string;
}
