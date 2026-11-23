import { AuthenticationService } from './authentication.service';
import { UserMetadataService } from './user-metadata.service';
import { model as mongooseModel } from 'mongoose';
import { UserSchema } from './schemas/user.schema';
import { Role } from '../enums/role.enum';

describe('Provider accounts', () => {
  const model = {
    findOne: jest.fn(),
    exists: jest.fn(),
    create: jest.fn(),
    findById: jest.fn(),
    updateOne: jest.fn(),
  };
  const hash = { hash: jest.fn(), compare: jest.fn() };
  const jwt = { signAsync: jest.fn() };
  let service: AuthenticationService;
  const account = {
    _id: 'uuid',
    email: 'user@example.com',
    role: Role.Regular,
  };
  beforeEach(() => {
    jest.resetAllMocks();
    service = new AuthenticationService(
      model as any,
      {} as any,
      hash,
      jwt as any,
      new UserMetadataService(),
    );
    jwt.signAsync.mockResolvedValue('token');
    jest.spyOn(service, 'ensureUserMetadata').mockResolvedValue(undefined);
  });
  it('creates a regular account without a password and initializes metadata under its UUID', async () => {
    model.findOne.mockResolvedValue(null);
    model.exists.mockResolvedValue(null);
    model.create.mockResolvedValue(account);
    await service.signInExternal('google', 'provider-sub', account.email);
    expect(model.create).toHaveBeenCalledWith({
      email: account.email,
      externalIdentities: ['google:provider-sub'],
    });
    expect(
      new (mongooseModel('SocialLoginTest', UserSchema))({
        email: account.email,
      }).role,
    ).toBe(Role.Regular);
    expect(service.ensureUserMetadata).toHaveBeenCalledWith(account, 'token');
    expect(hash.hash).not.toHaveBeenCalled();
  });
  it('reuses the original UUID and assigned role despite changed provider email', async () => {
    model.findOne.mockResolvedValue({ ...account, role: Role.Admin });
    await service.signInExternal('github', '123', 'new@example.com');
    expect(model.create).not.toHaveBeenCalled();
    expect(jwt.signAsync).toHaveBeenCalledWith(
      expect.objectContaining({ sub: 'uuid', role: Role.Admin }),
      expect.anything(),
    );
  });
  it('never merges with an existing email or mints a token for it', async () => {
    model.findOne.mockResolvedValue(null);
    model.exists.mockResolvedValue({ _id: 'someone-else' });
    await expect(
      service.signInExternal('apple', 'sub', account.email),
    ).rejects.toThrow('Account linking required');
    expect(model.create).not.toHaveBeenCalled();
    expect(jwt.signAsync).not.toHaveBeenCalled();
  });
  it('recovers a racing identical sign-up, but rejects a racing different identity', async () => {
    model.exists.mockResolvedValue(null);
    model.create.mockRejectedValue({ code: 11000 });
    model.findOne.mockResolvedValueOnce(null).mockResolvedValueOnce(account);
    await service.signInExternal('google', 'sub', account.email);
    model.findOne.mockResolvedValue(null);
    await expect(
      service.signInExternal('github', 'other', account.email),
    ).rejects.toThrow('Account linking required');
  });
  it('updates only the photo for the authenticated provider identity', async () => {
    const photo = 'https://avatars.githubusercontent.com/u/123?v=4';
    model.findOne.mockResolvedValue(account);
    await service.signInExternal('github', '123', account.email, photo);
    expect(model.updateOne).toHaveBeenCalledWith(
      { _id: account._id, externalIdentities: 'github:123' },
      { $set: { 'externalAvatars.github': photo } },
    );
  });
  it('returns only linked providers, their photos and password capability', async () => {
    const photo = 'https://lh3.googleusercontent.com/photo';
    const query = { select: jest.fn(), maxTimeMS: jest.fn(), exec: jest.fn() };
    query.select.mockReturnValue(query);
    query.maxTimeMS.mockReturnValue(query);
    query.exec.mockResolvedValue({
      password: 'stored-hash',
      externalIdentities: ['google:private-subject', 'github:123'],
      externalAvatars: new Map([
        ['google', photo],
        ['apple', 'unused'],
      ]),
    });
    model.findById.mockReturnValue(query);

    const accountId = '000000000000000000000001';
    expect(await service.getSignInMethods(accountId)).toStrictEqual({
      hasPassword: true,
      providers: [
        { provider: 'google', avatarUrl: photo },
        { provider: 'github', avatarUrl: undefined },
      ],
    });
    expect(model.findById).toHaveBeenCalledWith(accountId);
  });
  it('provider-only accounts cannot use password sign-in', async () => {
    model.findOne.mockResolvedValue(account);
    await expect(
      service.signIn({ email: account.email, password: 'anything' }),
    ).rejects.toThrow('Invalid credentials');
    expect(jwt.signAsync).not.toHaveBeenCalled();
    expect(hash.compare).not.toHaveBeenCalled();
  });
});
