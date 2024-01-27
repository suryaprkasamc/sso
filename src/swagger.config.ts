import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { INestApplication } from '@nestjs/common';

export function setupSwagger(app: INestApplication): void {
  const config = new DocumentBuilder()
    .setTitle('My Swagger App')
    .setDescription('API documentation for My Swagger App')
    .setVersion('1.0')
    .addTag('nestjs')
    .addBearerAuth() // Add this line to include a bearer token definition
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);
}
