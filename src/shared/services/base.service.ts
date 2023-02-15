import { Injectable } from '@nestjs/common';
import {
  BaseEntity,
  FindOptionsOrder,
  FindOptionsWhere,
  Repository,
} from 'typeorm';
import { Params } from '../dtos/params.utils';
import { MessageResponse } from '../dtos/shared.gql-types';
import { getIds, validateRequest } from '../helpers/base.helper';
import { sanitizeResponse } from '../helpers/sanitize.response';
import { GetOneBase, SearchOptions } from '../interfaces/base.interface';
import { FindOptions } from '../types/base.type';

@Injectable()
export class BaseService<T extends BaseEntity> {
  constructor(
    protected readonly repository: Repository<T>,
    protected readonly Model: any,
  ) {}

  findOne = async (payload: GetOneBase): Promise<T> => {
    validateRequest(payload.id);
    return await this.repository.findOneOrFail({
      where: { id: payload.id } as FindOptionsWhere<T> | FindOptionsWhere<any>,
      relations: payload.relations,
    });
  };
  deleteOne = async (id: string): Promise<MessageResponse> => {
    validateRequest(id);
    await this.repository.findOneOrFail({
      where: { id } as FindOptionsWhere<T> | FindOptionsWhere<any>,
      relations: [],
    });
    await this.repository.delete(id);
    return { message: `Entity with ${id} deleted` };
  };

  async findAll(
    params: Params,
    relations: any[],
    options: SearchOptions,
  ): Promise<any> {
    validateRequest(params);
    if (params?.search && params?.search !== '') {
      return await this.findSearch(params, relations, options);
    }
    if (params?.paging === false) {
      return await this.find(relations, options);
    } else {
      return await this.findAndCount(params, relations, options);
    }
  }

  create = async (entity: any, relations: string[]) => {
    validateRequest(entity);
    let newEntity: any = this.repository.create(entity);
    newEntity = await this.repository.save(newEntity);
    return sanitizeResponse(
      await this.repository.findOne({
        where: {
          id: newEntity.id as FindOptions,
        } as unknown as FindOptionsWhere<T>,
        relations,
      }),
    );
  };

  async update(id: string, entity: any, relations: any[]): Promise<T> {
    delete entity?.access;
    try {
      validateRequest(entity);
      const entityData = await this.findOne({ id, relations });
      await this.updateEntity(entityData, entity);
      return await this.findOne({ id, relations });
    } catch (e) {
      throw new Error(e.message);
    }
  }

  private updateEntity = async (
    entityData: any,
    entity: any,
  ): Promise<void> => {
    if (entity.email) {
      await this.updateEntityWithEmail(entityData, entity);
    } else {
      delete entity.password;
      await this.repository.save({ id: entityData.id, ...entity });
    }
    return;
  };

  private updateEntityWithEmail = async (entityData: any, entity: any) => {
    const verifiedUser = await this.Model.validatePassword(
      entity.password,
      entityData.salt,
      entityData?.password,
    );
    if (verifiedUser) {
      delete entity.password;
      await this.repository.save({ id: entityData.id, ...entity });
      return;
    } else {
      throw new Error('User could not be verified');
    }
  };

  private async find(
    relations: string[],
    options: SearchOptions,
  ): Promise<T[]> {
    return await this.repository.find({
      where: options.whereParams,
      order: {
        [options.params.property ? options.params.property : 'created']: options
          .params.direction
          ? options.params.direction
          : 'DESC',
      } as unknown as FindOptionsOrder<T>,
      relations,
    });
  }

  private async findAndCount(
    params: Params,
    relations: string[],
    options: SearchOptions,
  ): Promise<T[]> {
    const [entities, total] = await this.repository.findAndCount({
      take: +params?.pageSize || 100,
      skip: +params?.pageSize * (+params?.page - 1) || 0,
      relations,
      where: options.whereParams,
      order: {
        [options.params.property ? options.params.property : 'created']: options
          .params.direction
          ? options.params.direction
          : 'DESC',
      } as unknown as FindOptionsOrder<T>,
    });
    return entities.map((entity) => {
      return { ...entity, total };
    });
  }

  private async findSearch(
    params: Params,
    relations: any[],
    options: SearchOptions,
  ): Promise<any> {
    if (!params?.paging) {
      const entities = await this.repository
        .createQueryBuilder(options.table)
        .select(options.column)
        .where(options.query, options.params)
        .getMany();

      return (
        await this.repository.find({
          where: {
            id: getIds(entities) as FindOptions,
            ...options?.whereParams,
          } as unknown as FindOptionsWhere<T>,
          order: {
            [options.params.property ? options.params.property : 'created']:
              options.params.direction ? options.params.direction : 'DESC',
          } as unknown as FindOptionsOrder<T>,
          relations,
        })
      ).map((entity) => sanitizeResponse(entity));
    } else {
      return await this.findAndCountSearch(params, relations, options);
    }
  }

  private async findAndCountSearch(
    params: Params,
    relations: string[],
    options: SearchOptions,
  ): Promise<any> {
    const [entityData, total] = await this.repository
      .createQueryBuilder(options.table)
      .select(options.column)
      .where(options.query, options.params)
      .take(+params?.pageSize || 100)
      .skip(+params?.pageSize * (Number(params?.page) - 1) || 0)
      .getManyAndCount();
    if (total === 0) {
      return [];
    }

    return (
      await this.repository.find({
        where: {
          id: getIds(entityData) as FindOptions,
          ...options?.whereParams,
        } as unknown as FindOptionsWhere<T>,
        relations,
        order: {
          [options.params.property ? options.params.property : 'created']:
            options.params.direction ? options.params.direction : 'DESC',
        } as unknown as FindOptionsOrder<T>,
      })
    ).map((entity) => sanitizeResponse({ ...entity, total }));
  }
}
