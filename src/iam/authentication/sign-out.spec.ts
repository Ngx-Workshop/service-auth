import type { Response } from 'express';
import { AuthenticationController } from './authentication.controller';
import type { AuthenticationService } from './authentication.service';

it('clears the same domain and path as the browser sign-in cookie', async () => {
  const auth = {
    signIn: jest.fn().mockResolvedValue({ accessToken: 'test-token' }),
  } as unknown as AuthenticationService;
  const response = {
    cookie: jest.fn(),
    clearCookie: jest.fn(),
    end: jest.fn(),
  };
  const controller = new AuthenticationController(auth);
  await controller.signIn(response as unknown as Response, {
    email: 'user@example.com',
    password: 'ExamplePassword123',
  });
  await controller.signOut(response as unknown as Response);

  const [name, , options] = response.cookie.mock.calls[0];
  expect(options).toEqual(
    expect.objectContaining({ domain: expect.any(String), path: '/' }),
  );
  expect(response.clearCookie).toHaveBeenCalledWith(name, options);
  expect(response.end).toHaveBeenCalledTimes(1);
});
