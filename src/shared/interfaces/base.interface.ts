export interface GetOneBase {
  relations: string[];
  id: string;
}

export interface SearchOptions {
  query: string;
  params: any;
  table: string;
  column: string;
  whereParams?: any;
}
