import { registerAs } from '@nestjs/config';

export default registerAs('jwt', () => ({
  secret: process.env.JWT_SECRET,
  issuer: process.env.JWT_ISSUER,
  audience: process.env.JWT_AUDIENCE,
  accessTokenTtl: +process.env.JWT_ACCESS_TOKEN_TTL! || 3600,
  refreshTokenTtl: +process.env.JWT_REFRESH_TOKEN_TTL! || 86400,
}));