import { Logger, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module';
import { HttpErrorFilter } from './core/interceptors/errors.interceptor';
import { LoggingInterceptor } from './core/interceptors/logging.interceptor';
import * as createRedisStore from 'connect-redis';
import * as session from 'express-session';
import * as passport from 'passport';
import { createClient } from 'redis';
import { ConfigService } from '@nestjs/config';

const bootstrap = async () => {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    cors: true,
  });

  const configService = app.get(ConfigService);

  const RedisStore = createRedisStore(session);
  const host: string = configService.get('REDIS_HOST');
  const port = Number(configService.get('REDIS_PORT'));
  const redisClient = createClient({
    socket: {
      host,
      port,
    },
    legacyMode: true,
  });

  await redisClient.connect();

  redisClient.on('error', (err) =>
    Logger.error('Could not establish a connection with redis. ' + err),
  );

  redisClient.on('connect', () =>
    Logger.verbose('Connected to redis successfully'),
  );
  app.use(
    session({
      store: new RedisStore({ client: redisClient as any }),
      secret: configService.get('COOKIE_SECRET'),
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'prod',
      },
    }),
  );

  app.use(passport.initialize());
  app.use(passport.session());

  app.useGlobalInterceptors(new LoggingInterceptor());
  app.useGlobalFilters(new HttpErrorFilter());
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      forbidUnknownValues: false,
      skipMissingProperties: true,
    }),
  );
  const PORT = process.env.PORT || 3000;
  app.disable('x-powered-by');
  await app.listen(PORT);
  Logger.debug(`App Listening on Port: ${PORT}`, 'APP');
};
bootstrap();
