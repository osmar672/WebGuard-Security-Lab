import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, ShieldCheck } from 'lucide-react';
import { signIn } from '../api/authService';

export function LoginPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError('');
    setBusy(true);
    try {
      await signIn(email.trim(), password);
      navigate('/', { replace: true });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to sign in.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-card" aria-labelledby="login-title">
        <div className="login-brand-mark"><ShieldCheck size={26} aria-hidden="true" /></div>
        <p className="eyebrow">WEBGUARD SECURITY LAB</p>
        <h1 id="login-title">Sign in to your workspace</h1>
        <p className="login-description">Authorized security testing and assessment management.</p>
        <form onSubmit={submit} className="login-form">
          <label htmlFor="login-email">Email address</label>
          <input
            id="login-email"
            name="email"
            type="email"
            autoComplete="username"
            required
            maxLength={254}
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
          <label htmlFor="login-password">Password</label>
          <input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            maxLength={1024}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
          {error && <p className="login-error" role="alert">{error}</p>}
          <button className="login-submit" type="submit" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'} <ArrowRight size={17} aria-hidden="true" />
          </button>
        </form>
        <p className="login-footnote">Accounts are created by a system administrator. Public registration is disabled.</p>
      </section>
    </main>
  );
}
