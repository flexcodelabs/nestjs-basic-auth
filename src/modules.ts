import { ConfigModule } from '@nestjs/config';
import { UserModule } from './modules/user/user.module';

export const MODULES = [UserModule, ConfigModule.forRoot()];
