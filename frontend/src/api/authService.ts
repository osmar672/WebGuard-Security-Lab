import { postJson } from './httpClient';
import { setAccessToken, setSessionUser, type SessionUser } from './session';

interface LoginPayload {
  access_token: string;
  token_type: 'bearer';
  expires_in: number;
  user: SessionUser;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function decodeLogin(value: unknown): LoginPayload {
  if (!isObject(value) || typeof value.access_token !== 'string' || value.token_type !== 'bearer'
      || typeof value.expires_in !== 'number' || !isObject(value.user)) {
    throw new Error('Invalid login response from API.');
  }
  const user = value.user;
  if (typeof user.id !== 'string' || typeof user.email !== 'string'
      || !['admin', 'operator', 'viewer'].includes(String(user.role))
      || typeof user.is_active !== 'boolean' || typeof user.created_at !== 'string') {
    throw new Error('User information in the login response is invalid.');
  }
  return {
    access_token: value.access_token,
    token_type: 'bearer',
    expires_in: value.expires_in,
    user: {
      id: user.id,
      email: user.email,
      role: user.role as SessionUser['role'],
      is_active: user.is_active,
      created_at: user.created_at,
    },
  };
}

export async function signIn(email: string, password: string): Promise<SessionUser> {
  const result = await postJson('/api/auth/login', { email, password }, decodeLogin, true);
  setAccessToken(result.access_token);
  setSessionUser(result.user);
  return result.user;
}
