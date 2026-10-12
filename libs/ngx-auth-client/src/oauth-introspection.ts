import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';

export interface OAuthPrincipal {
  readonly issuer: string;
  readonly subject: string;
  readonly clientId: string;
  readonly audience: string;
  readonly scopes: readonly string[];
  readonly issuedAt: number;
  readonly expiresAt: number;
}
export type OAuthVerificationFailure =
  | 'invalid_token'
  | 'auth_unavailable'
  | 'invalid_auth_response';
export class OAuthVerificationError extends Error {
  constructor(public readonly category: OAuthVerificationFailure) {
    super(category);
    this.name = 'OAuthVerificationError';
  }
}
export interface OAuthIntrospectionOptions {
  issuer: string;
  introspectionUrl: string;
  resource: string;
  clientId: string;
  clientSecret: string;
  allowLocalHttp?: boolean;
  timeoutMs?: number;
  maxResponseBytes?: number;
}
function canonical(value: string, allowLocalHttp: boolean): URL {
  const url = new URL(value);
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    value !== url.href.replace(/\/$/, '') ||
    !(
      url.protocol === 'https:' ||
      (allowLocalHttp &&
        url.protocol === 'http:' &&
        ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname))
    )
  )
    throw new Error('Invalid OAuth client URL');
  return url;
}
export class OAuthIntrospectionClient {
  private readonly endpoint: URL;
  private readonly options: Readonly<OAuthIntrospectionOptions>;
  constructor(options: OAuthIntrospectionOptions) {
    this.options = Object.freeze({ ...options });
    const issuer = canonical(options.issuer, options.allowLocalHttp === true);
    canonical(options.resource, options.allowLocalHttp === true);
    this.endpoint = canonical(
      options.introspectionUrl,
      options.allowLocalHttp === true,
    );
    if (
      this.endpoint.origin !== issuer.origin ||
      this.endpoint.pathname !== '/oauth/introspect' ||
      issuer.pathname !== '/' ||
      !options.clientId ||
      options.clientId.includes(':') ||
      !options.clientSecret ||
      (options.timeoutMs !== undefined &&
        (!Number.isInteger(options.timeoutMs) ||
          options.timeoutMs < 1 ||
          options.timeoutMs > 10000)) ||
      (options.maxResponseBytes !== undefined &&
        (!Number.isInteger(options.maxResponseBytes) ||
          options.maxResponseBytes < 1 ||
          options.maxResponseBytes > 65536))
    )
      throw new Error('Invalid OAuth introspection configuration');
  }
  async verifyAccessToken(token: string): Promise<OAuthPrincipal> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(token))
      throw new OAuthVerificationError('invalid_token');
    const data: unknown = await new Promise((resolve, reject) => {
      const body = new URLSearchParams({
        token,
        token_type_hint: 'access_token',
      }).toString();
      const request = (
        this.endpoint.protocol === 'https:' ? httpsRequest : httpRequest
      )(
        this.endpoint,
        {
          method: 'POST',
          agent: false,
          headers: {
            authorization: `Basic ${Buffer.from(`${this.options.clientId}:${this.options.clientSecret}`).toString('base64')}`,
            'content-type': 'application/x-www-form-urlencoded',
            'content-length': Buffer.byteLength(body),
            accept: 'application/json',
          },
        },
        (response) => {
          if (response.statusCode !== 200) {
            response.destroy();
            reject(new OAuthVerificationError('auth_unavailable'));
            return;
          }
          if (
            response.headers['content-type']?.split(';')[0] !==
            'application/json'
          ) {
            response.destroy();
            reject(new OAuthVerificationError('invalid_auth_response'));
            return;
          }
          let bytes = 0;
          const chunks: Buffer[] = [];
          response.on('data', (chunk: Buffer) => {
            bytes += chunk.length;
            if (bytes > (this.options.maxResponseBytes ?? 65536)) {
              response.destroy();
              reject(new OAuthVerificationError('invalid_auth_response'));
            } else chunks.push(chunk);
          });
          response.on('error', () =>
            reject(new OAuthVerificationError('auth_unavailable')),
          );
          response.on('end', () => {
            try {
              resolve(JSON.parse(Buffer.concat(chunks).toString()) as unknown);
            } catch {
              reject(new OAuthVerificationError('invalid_auth_response'));
            }
          });
        },
      );
      const timer = setTimeout(() => {
        request.destroy();
        reject(new OAuthVerificationError('auth_unavailable'));
      }, this.options.timeoutMs ?? 3000);
      request.on('close', () => clearTimeout(timer));
      request.on('error', () =>
        reject(new OAuthVerificationError('auth_unavailable')),
      );
      request.end(body);
    });
    if (typeof data !== 'object' || !data || Array.isArray(data))
      throw new OAuthVerificationError('invalid_auth_response');
    const value = data as Record<string, unknown>;
    if (value.active === false)
      throw new OAuthVerificationError('invalid_token');
    if (
      value.active !== true ||
      value.token_type !== 'Bearer' ||
      !['iss', 'sub', 'client_id', 'aud', 'scope'].every(
        (key) => typeof value[key] === 'string' && value[key].length > 0,
      ) ||
      !Number.isSafeInteger(value.exp) ||
      !Number.isSafeInteger(value.iat)
    )
      throw new OAuthVerificationError('invalid_auth_response');
    const now = Math.floor(Date.now() / 1000),
      exp = value.exp as number,
      iat = value.iat as number;
    if (
      value.iss !== this.options.issuer ||
      value.aud !== this.options.resource ||
      exp <= now ||
      iat > now ||
      iat < 0 ||
      iat >= exp
    )
      throw new OAuthVerificationError('invalid_token');
    if (
      !/^[\x21\x23-\x5b\x5d-\x7e]+(?: [\x21\x23-\x5b\x5d-\x7e]+)*$/.test(
        value.scope as string,
      )
    )
      throw new OAuthVerificationError('invalid_auth_response');
    return Object.freeze({
      issuer: value.iss,
      subject: value.sub as string,
      clientId: value.client_id as string,
      audience: value.aud,
      scopes: Object.freeze((value.scope as string).split(' ')),
      issuedAt: iat,
      expiresAt: exp,
    });
  }
}
