import { NotAcceptableException } from '@nestjs/common';
import { ILike, In } from 'typeorm';
import { GenericFilter } from '../dtos/params.utils';

export const getIds = (entityData) => {
  return In(entityData.map(({ id }) => id));
};

export const validateRequest = (request: unknown) => {
  const sqlInjection = /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/;
  if (!Array.isArray(request) && typeof request === 'object') {
    Object.values(request).forEach((value) => {
      if (sqlInjection.test(value))
        throw new NotAcceptableException('Malicious request detected');
    });
  }

  if (Array.isArray(request)) {
    request.forEach((data) => validateRequest(data));
  }

  if (typeof request === 'string' && sqlInjection.test(request)) {
    throw new NotAcceptableException('Malicious request detected');
  }
};

export const getFilters = (filters: GenericFilter[]) => {
  if (filters) {
    return Object.assign(
      {},
      ...filters.map((filter) => {
        return { [filter.key]: ILike(`%${filter.value}%`) };
      }),
    );
  }
  return [];
};
