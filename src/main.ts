import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { setupSwagger } from './swagger.config';
import * as session from 'express-session';
import * as passport from 'passport';
import * as dotenv from 'dotenv';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(
    session({
      secret: 'my-secret',
      resave: false,
      saveUninitialized: false,
      cookie: {
        maxAge: 60000,
      },
    }),
  );
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(passport.initialize());
  app.use(passport.session());
  app.enableCors({
    origin: '*', // Replace with your actual frontend domain
    credentials: true,
  });
  setupSwagger(app);
  await app.listen(3000);
}
bootstrap();
