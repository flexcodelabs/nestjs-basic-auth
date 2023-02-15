import { Field, InputType, ObjectType } from '@nestjs/graphql';
import { IsEmail, IsStrongPassword } from 'class-validator';

@InputType()
export class UserInput {
  @IsEmail()
  @Field({
    nullable: false,
  })
  email: string;

  @Field({
    nullable: false,
  })
  name: string;

  @Field({
    nullable: false,
  })
  username: string;

  @IsStrongPassword()
  @Field({
    nullable: false,
  })
  password: string;
}

@InputType()
export class UpdatePassword {
  @Field({ nullable: false })
  oldPassword: string;

  @Field({ nullable: false })
  newPassword: string;
}

@InputType()
export class UserRelation {
  @Field({ nullable: false })
  id: string;

  @Field({
    nullable: true,
  })
  username?: string;

  @Field({
    nullable: true,
  })
  name?: string;
}

@InputType()
export class UserUpdate {
  @IsEmail()
  @Field({
    nullable: true,
  })
  email?: string;

  @Field({
    nullable: true,
  })
  name: string;

  @Field({
    nullable: true,
  })
  username?: string;

  @Field({
    nullable: true,
  })
  password: string;
}

export class UserData {
  @Field({
    nullable: true,
  })
  id: string;

  @Field({
    nullable: true,
  })
  username?: string;

  @Field()
  name: string;

  @Field({
    nullable: true,
  })
  created?: Date;

  @Field({
    nullable: true,
  })
  lastUpdated?: Date;
}

@InputType()
export class Login {
  @Field({
    nullable: false,
  })
  password: string;

  @Field({
    nullable: false,
  })
  email: string;
}

@ObjectType()
export class Logout {
  @Field()
  message: string;
}
