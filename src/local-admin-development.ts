import { ForbiddenException } from '@nestjs/common';
import { Request } from 'express';
import { RequestKeys } from './iam/enums/request-keys.emun';
import { Role } from './iam/enums/role.enum';
export const localAdminMode = () =>
  process.env.AUTH_ADMIN_LOCAL_DEV === 'true' &&
  process.env.NODE_ENV === 'development';
export function assertLocalAdminMode() {
  if (process.env.AUTH_ADMIN_LOCAL_DEV !== 'true') return;
  if (
    !localAdminMode() ||
    process.env.MONGODB_URI !== 'mongodb://127.0.0.1:27017/auth_users_local' ||
    process.env.OAUTH_ENABLED === 'true'
  )
    throw new Error(
      'Local admin auth requires development, isolated auth_users_local on loopback and OAuth disabled',
    );
}
export function authenticateLocalProvisioning(request: Request): boolean {
  if (
    !localAdminMode() ||
    !(
      (request.method === 'POST' && request.path === '/admin/users') ||
      (request.method === 'PUT' && request.path === '/role')
    )
  )
    return false;
  assertLocalAdminMode();
  if (
    !['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(
      request.socket.remoteAddress ?? '',
    ) ||
    (request.headers.origin !== undefined &&
      !['http://localhost:3004', 'http://127.0.0.1:3004'].includes(
        request.headers.origin,
      ))
  )
    throw new ForbiddenException(
      'Local provisioning requires loopback metadata service',
    );
  request[RequestKeys.REQUEST_USER_KEY] = {
    sub: 'local-user-metadata-admin',
    email: 'local-admin@example.invalid',
    role: Role.Admin,
  };
  return true;
}
