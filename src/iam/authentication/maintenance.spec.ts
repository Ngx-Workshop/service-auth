import { Test } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Logger } from '@nestjs/common';
import axios from 'axios';
import type { Response } from 'express';
import jwtConfig from '../config/jwt.config';
import { HashingService } from '../hashing/hashing.service';
import { Role } from '../enums/role.enum';
import { AuthenticationController } from './authentication.controller';
import { AuthenticationService } from './authentication.service';
import { User } from './schemas/user.schema';
import { UserMetadataService } from './user-metadata.service';

describe('Maintenance compatibility boundaries', () => {
  const dto = {
    email: 'canary-email@example.invalid',
    password: 'canary-pass1',
  };
  const user = {
    _id: '000000000000000000000001',
    email: dto.email,
    password: 'canary-hash',
    role: Role.Regular,
  };
  const model = {
    create: jest.fn(),
    findOne: jest.fn(),
    findByIdAndUpdate: jest.fn(),
  };
  const hash = { hash: jest.fn(), compare: jest.fn() };
  const jwt = { signAsync: jest.fn() };
  const response = { cookie: jest.fn() };
  let controller: AuthenticationController;
  let service: AuthenticationService;
  let put: jest.SpyInstance;
  let log: jest.SpyInstance;
  let warn: jest.SpyInstance;
  let error: jest.SpyInstance;

  beforeEach(async () => {
    jest.resetAllMocks();
    log = jest
      .spyOn(Logger.prototype, 'log')
      .mockImplementation(() => undefined);
    warn = jest
      .spyOn(Logger.prototype, 'warn')
      .mockImplementation(() => undefined);
    error = jest
      .spyOn(Logger.prototype, 'error')
      .mockImplementation(() => undefined);
    const client = axios.create();
    put = jest.spyOn(client, 'put').mockResolvedValue({ status: 200 });
    jest.spyOn(axios, 'create').mockReturnValue(client);
    const module = await Test.createTestingModule({
      controllers: [AuthenticationController],
      providers: [
        AuthenticationService,
        UserMetadataService,
        { provide: getModelToken(User.name), useValue: model },
        { provide: jwtConfig.KEY, useValue: {} },
        { provide: HashingService, useValue: hash },
        { provide: JwtService, useValue: jwt },
      ],
    }).compile();
    controller = module.get(AuthenticationController);
    service = module.get(AuthenticationService);
    model.create.mockResolvedValue(user);
    model.findOne.mockResolvedValue(user);
    hash.hash.mockResolvedValue(user.password);
    hash.compare.mockResolvedValue(true);
    jwt.signAsync.mockResolvedValue('canary-token');
  });

  afterEach(() => jest.restoreAllMocks());

  it('registers, verifies, signs and upserts before setting the unchanged cookie', async () => {
    expect(
      await controller.signUp(response as unknown as Response, dto),
    ).toBeUndefined();
    expect(hash.hash).toHaveBeenCalledWith(dto.password);
    expect(hash.compare).toHaveBeenCalledWith(dto.password, user.password);
    expect(jwt.signAsync).toHaveBeenCalledTimes(2);
    expect(put).toHaveBeenCalledWith(
      '/user-metadata',
      { uuid: user._id },
      { headers: { Authorization: 'Bearer canary-token' } },
    );
    expect(response.cookie).toHaveBeenCalledWith(
      'accessToken',
      'canary-token',
      expect.objectContaining({ path: '/', httpOnly: true, sameSite: true }),
    );
  });

  it('keeps metadata failure best-effort but never sets a cookie after storage failure', async () => {
    put.mockRejectedValue(new Error('canary-upstream-secret'));
    await controller.signUp(response as unknown as Response, dto);
    expect(response.cookie).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'user_metadata_upsert',
        outcome: 'failure',
      }),
    );
    expect(
      JSON.stringify([log.mock.calls, warn.mock.calls, error.mock.calls]),
    ).not.toContain('canary');
    response.cookie.mockClear();
    model.create.mockRejectedValue(new Error('storage unavailable'));
    await expect(
      controller.signUp(response as unknown as Response, dto),
    ).rejects.toThrow('storage unavailable');
    expect(response.cookie).not.toHaveBeenCalled();
  });

  it('preserves duplicate-account conflict and invalid-password denial without minting tokens', async () => {
    model.create.mockRejectedValue({ code: 11000 });
    await expect(
      controller.signUp(response as unknown as Response, dto),
    ).rejects.toThrow('Email already exists');
    hash.compare.mockResolvedValue(false);
    await expect(service.signIn(dto)).rejects.toThrow('Invalid password');
    expect(jwt.signAsync).not.toHaveBeenCalled();
    expect(response.cookie).not.toHaveBeenCalled();
  });

  it('retains role-update options, null not-found and storage failure semantics', async () => {
    const exec = jest.fn().mockResolvedValue(null);
    model.findByIdAndUpdate.mockReturnValue({ exec });
    expect(
      await service.updateUserRole({ userId: user._id, role: Role.Publisher }),
    ).toBeNull();
    expect(model.findByIdAndUpdate).toHaveBeenCalledWith(
      expect.anything(),
      { role: Role.Publisher },
      { new: true, runValidators: true },
    );
    exec.mockRejectedValue(new Error('storage unavailable'));
    await expect(
      service.updateUserRole({ userId: user._id, role: Role.Admin }),
    ).rejects.toThrow('storage unavailable');
  });
});
