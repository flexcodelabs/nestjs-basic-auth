import { Field, ObjectType } from '@nestjs/graphql';
import * as bcrypt from 'bcrypt';
import {
  BaseEntity,
  BeforeInsert,
  BeforeUpdate,
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@ObjectType()
@Entity('user', { schema: 'public' })
export class User extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  @Field()
  id?: string;

  @CreateDateColumn({ type: 'timestamp', default: () => 'LOCALTIMESTAMP' })
  @Field({
    nullable: false,
  })
  created?: Date;

  @UpdateDateColumn({
    type: 'timestamp',
    name: 'lastupdated',
    default: () => 'LOCALTIMESTAMP',
  })
  @Field({
    nullable: false,
  })
  lastUpdated?: Date;

  @Column({ name: 'name', nullable: false, unique: false })
  @Field()
  name: string;

  @Column({ name: 'username', nullable: false, unique: false })
  @Field()
  username: string;

  @Column({ unique: true, nullable: false })
  // @Field({ nullable: false })
  email: string;

  @Column({ nullable: false })
  password: string;

  @Column({ nullable: false })
  salt?: string;

  @Field({
    nullable: true,
  })
  total?: number;

  @BeforeInsert()
  async beforeInsertTransaction() {
    this.created = new Date();
    this.lastUpdated = new Date();
    this.salt = await bcrypt.genSalt();
    this.password = await this.hashPassword(this.password, this.salt);
  }

  @BeforeUpdate()
  async beforeUpdateTransaction() {
    this.lastUpdated = this.lastUpdated || new Date();
  }

  public static async authenticateUser(
    username: string,
    password: string,
  ): Promise<User> {
    const user: User = await User.findOne({
      where: { username },
    });
    if (
      user &&
      (await this.validatePassword(password, user.salt, user.password))
    ) {
      delete user.password;
      return user;
    } else {
      return null;
    }
  }

  async hashPassword(password: string, salt: string): Promise<any> {
    return bcrypt.hash(password, salt);
  }
  public static async verifyUser(username: any, password: any): Promise<any> {
    const user = await this.getUser(username);
    if (
      user &&
      (await this.validatePassword(password, user?.salt, user?.password))
    ) {
      delete user.password;
      delete user.salt;
      return user;
    } else {
      const isEmail = /^\S+@\S+$/;
      throw new Error(
        `Invalid ${isEmail.test(username) ? 'Email' : 'Username'} or Password`,
      );
    }
  }
  public static getUser = async (email: string) => {
    const isEmail = /^\S+@\S+$/;
    const user: User = await User.findOne({
      where: { [isEmail.test(email) ? 'email' : 'username']: email },
    });

    return user;
  };
  public static async validatePassword(
    plainPassword: string,
    salt: string,
    hashedPassword: string,
  ): Promise<boolean> {
    const passwordHash = await bcrypt.hash(plainPassword, salt);
    return passwordHash === hashedPassword;
  }
}
