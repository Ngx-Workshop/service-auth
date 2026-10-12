import { createAuthApp } from './bootstrap';

async function bootstrap() {
  const { app, host } = await createAuthApp();
  await app.listen(process.env.PORT ?? 3000, host);
}
void bootstrap();
