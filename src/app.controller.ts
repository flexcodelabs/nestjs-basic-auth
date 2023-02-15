import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getStatus(): { status: string } {
    return { status: 'Up and Running ✅' };
  }

  @Get('images/icons/gear.png')
  icon(): { status: string } {
    return { status: 'Up and Running ✅' };
  }

  @Get('favicon.ico')
  gear(): { status: string } {
    return { status: 'Up and Running ✅' };
  }
}
