import { FindOptionsWhere } from 'typeorm';

export type FindOptions = FindOptionsWhere<any> | FindOptionsWhere<any>[];
