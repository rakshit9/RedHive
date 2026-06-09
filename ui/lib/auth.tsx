"use client";

// Client-side auth context. Holds the session token + org profile, exposes
// login/signup/logout, and gates the app shell. The token lives in
// localStorage (see lib/api.ts) so it survives reloads.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { useRouter } from "next/navigation";
import * as api from "@/lib/api";

interface AuthState {
  ready: boolean; // finished the initial token check
  authed: boolean;
  me: api.Me | null;
  login: (email: string, password: string) => Promise<void>;
  signup: (
    org: string,
    email: string,
    password: string
  ) => Promise<api.AuthResult>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [me, setMe] = useState<api.Me | null>(null);

  const refresh = useCallback(async () => {
    if (!api.getToken()) {
      setMe(null);
      setReady(true);
      return;
    }
    try {
      setMe(await api.me());
    } catch {
      api.setToken(null);
      setMe(null);
    } finally {
      setReady(true);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const login = useCallback(
    async (email: string, password: string) => {
      const res = await api.login(email, password);
      api.setToken(res.token);
      await refresh();
      router.push("/");
    },
    [refresh, router]
  );

  const signup = useCallback(
    async (org: string, email: string, password: string) => {
      const res = await api.signup(org, email, password);
      api.setToken(res.token);
      await refresh();
      return res;
    },
    [refresh]
  );

  const logout = useCallback(() => {
    api.setToken(null);
    setMe(null);
    router.push("/login");
  }, [router]);

  return (
    <AuthContext.Provider
      value={{ ready, authed: !!me, me, login, signup, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
