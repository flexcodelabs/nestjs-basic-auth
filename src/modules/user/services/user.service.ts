import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { Repository } from 'typeorm';
import { sanitizeResponse } from '../../../shared/helpers/sanitize.response';
import { BaseService } from '../../../shared/services/base.service';
import { UpdatePassword } from '../dtos/user.dto';
import { User } from '../entities/user.entity';

@Injectable()
export class UserService extends BaseService<User> {
  constructor(@InjectRepository(User) readonly repository: Repository<User>) {
    super(repository, User);
  }

  async updatePassword(
    id: string,
    user: UpdatePassword,
    fields: any[],
  ): Promise<UpdatePassword> {
    const userUpdated = await this.findOneInternal(id, []);
    await this.validateUser(user, userUpdated);
    try {
      const salt = await bcrypt.genSalt();
      userUpdated.password = await this.hashPassword({
        salt,
        password: user.newPassword,
      });
      userUpdated.salt = salt;
      await this.repository.save(userUpdated);
      return sanitizeResponse(await this.findOneInternal(id, fields));
    } catch (e) {
      throw new Error(e.message);
    }
  }

  private validateUser = async (
    user: UpdatePassword,
    userUpdated: User,
  ): Promise<void> => {
    const message =
      userUpdated &&
      !(await this.validatePassword(
        user.oldPassword,
        userUpdated.salt,
        userUpdated.password,
      ))
        ? 'Wrong old/current password.'
        : user.newPassword === user.oldPassword
        ? 'New Password can not be the same as the old password.'
        : null;
    if (message) throw new BadRequestException(message);
  };

  private async findOneInternal(
    id: string,
    relations: string[],
  ): Promise<User> {
    return await this.repository.findOne({
      where: { id },
      relations,
    });
  }

  private validatePassword = async (
    oldpassword: string,
    salt: string,
    userpassword: string,
  ): Promise<boolean> => {
    const hash = await bcrypt.hash(oldpassword, salt);
    return hash === userpassword;
  };

  private hashPassword = async ({ password, salt }): Promise<string> => {
    return bcrypt.hash(password, salt);
  };
}
