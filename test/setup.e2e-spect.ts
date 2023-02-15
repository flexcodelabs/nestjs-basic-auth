import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { AppModule } from '../src/app.module';

export let app: INestApplication;
export const setUpServer = async () => {
  if (!app) {
    const imports: any[] = [AppModule];
    app = (
      await Test.createTestingModule({
        imports,
      }).compile()
    ).createNestApplication();
    await app.init();
    return app;
  } else {
    app.close();
  }
};

export const tearDownServer = async () => {
  if (app) {
    await app.close();
  }
};
