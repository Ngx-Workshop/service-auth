import { Reflector } from '@nestjs/core';
import { RolesGuard } from '../authorization/guards/roles.guard';
import { AuthenticationGuard } from './guards/authentication.guard';
import { AuthenticationService } from './authentication.service';
import { AuthenticationController } from './authentication.controller';
import { Role } from '../enums/role.enum';
import { AdminCreateUserDto } from './dto/admin-create-user.dto';
import {
  assertLocalAdminMode,
  authenticateLocalProvisioning,
} from '../../local-admin-development';
import { validate } from 'class-validator';
const dto: AdminCreateUserDto = {
  email: 'user@example.invalid',
  password: 'Examplepass12345',
  role: Role.Regular,
  requestId: 'bd769501-b715-4569-9206-381deee177ef',
};
describe('Administrator account provisioning', () => {
  const model = { findOne: jest.fn(), create: jest.fn() };
  const hash = { hash: jest.fn(), compare: jest.fn() };
  let service: AuthenticationService;
  beforeEach(() => {
    jest.resetAllMocks();
    service = new AuthenticationService(
      model as any,
      {} as any,
      hash,
      {} as any,
    );
  });
  const account = {
    _id: 'account-id',
    email: dto.email,
    role: Role.Regular,
    provisioningRequestId: dto.requestId,
    provisioningActor: 'admin-id',
    password: 'hashed',
  };
  it('hashes once and returns only identity fields without signing in the admin', async () => {
    model.findOne.mockResolvedValue(null);
    hash.hash.mockResolvedValue('hashed');
    model.create.mockResolvedValue(account);
    expect(await service.provisionUser(dto, 'admin-id')).toEqual({
      uuid: 'account-id',
      email: dto.email,
      role: Role.Regular,
    });
    expect(model.create).toHaveBeenCalledWith(
      expect.objectContaining({
        password: 'hashed',
        provisioningActor: 'admin-id',
      }),
    );
    expect(hash.hash).toHaveBeenCalledWith(dto.password);
    expect(
      Reflect.getMetadata(
        'roles',
        AuthenticationController.prototype.createUser,
      ),
    ).toEqual([Role.Admin]);
  });
  it('recovers the same account on retry without changing its password', async () => {
    model.findOne.mockResolvedValue(account);
    expect((await service.provisionUser(dto, 'admin-id')).uuid).toBe(
      'account-id',
    );
    expect(hash.hash).not.toHaveBeenCalled();
    expect(model.create).not.toHaveBeenCalled();
  });
  it('never attaches an unrelated existing email and recovers a concurrent identical operation', async () => {
    model.findOne.mockResolvedValue(null);
    model.create.mockRejectedValue({ code: 11000 });
    await expect(service.provisionUser(dto, 'admin-id')).rejects.toThrow(
      'Email already exists',
    );
    model.findOne
      .mockReset()
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(account);
    expect((await service.provisionUser(dto, 'admin-id')).uuid).toBe(
      'account-id',
    );
  });
  it('rejects request-ID reuse across actors or account identities', async () => {
    model.findOne.mockResolvedValue(account);
    await expect(service.provisionUser(dto, 'other-admin')).rejects.toThrow(
      'conflicts',
    );
    await expect(
      service.provisionUser(
        { ...dto, email: 'different@example.invalid' },
        'admin-id',
      ),
    ).rejects.toThrow('conflicts');
  });
  it('requires ordinary authentication and rejects non-admin roles outside isolated local mode', async () => {
    const previous = process.env.AUTH_ADMIN_LOCAL_DEV;
    delete process.env.AUTH_ADMIN_LOCAL_DEV;
    try {
      const request = {
        method: 'POST',
        path: '/admin/users',
        user: { role: Role.Regular },
      };
      const context = {
        getHandler: () => AuthenticationController.prototype.createUser,
        getClass: () => AuthenticationController,
        switchToHttp: () => ({ getRequest: () => request }),
      } as any;
      const auth = new AuthenticationGuard(new Reflector(), {
        canActivate: () => false,
      } as any);
      await expect(auth.canActivate(context)).rejects.toThrow(
        'Authentication failed',
      );
      const roles = new RolesGuard(new Reflector());
      expect(roles.canActivate(context)).toBe(false);
      request.user.role = Role.Admin;
      expect(roles.canActivate(context)).toBe(true);
    } finally {
      if (previous !== undefined) process.env.AUTH_ADMIN_LOCAL_DEV = previous;
    }
  });
  it('validates credentials, role and idempotency UUID', async () => {
    expect(
      await validate(Object.assign(new AdminCreateUserDto(), dto)),
    ).toHaveLength(0);
    expect(
      (
        await validate(
          Object.assign(new AdminCreateUserDto(), {
            ...dto,
            email: 'invalid',
            password: 'short1',
            role: 'owner',
            requestId: 'bad',
          }),
        )
      ).length,
    ).toBeGreaterThanOrEqual(4);
  });
});
describe('Isolated local provisioning boundary', () => {
  const original = { ...process.env };
  afterEach(() => {
    process.env = { ...original };
  });
  it('fails closed outside the explicit development database and never bypasses ordinary routes', () => {
    process.env.AUTH_ADMIN_LOCAL_DEV = 'true';
    process.env.NODE_ENV = 'production';
    expect(() => assertLocalAdminMode()).toThrow();
    process.env.NODE_ENV = 'development';
    process.env.MONGODB_URI = 'mongodb://127.0.0.1:27017/auth_users_local';
    process.env.OAUTH_ENABLED = 'false';
    expect(() => assertLocalAdminMode()).not.toThrow();
    expect(
      authenticateLocalProvisioning({
        method: 'GET',
        path: '/user-metadata',
      } as any),
    ).toBe(false);
    expect(() =>
      authenticateLocalProvisioning({
        method: 'POST',
        path: '/admin/users',
        socket: { remoteAddress: '10.0.0.2' },
        headers: {},
      } as any),
    ).toThrow();
    expect(
      authenticateLocalProvisioning({
        method: 'POST',
        path: '/admin/users',
        socket: { remoteAddress: '127.0.0.1' },
        headers: {},
      } as any),
    ).toBe(true);
  });
});
