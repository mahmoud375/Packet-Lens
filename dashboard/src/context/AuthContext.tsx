"use client";

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import api from "@/services/api";

// ─── Types ───────────────────────────────────────────────────────────────────

interface AuthUser {
  username: string;
  role: string;
  token: string;
  expiresAt: number;
}

interface AuthContextValue {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  token: string | null;
}

// ─── Storage Keys ────────────────────────────────────────────────────────────

const STORAGE_KEY = "packetlens_auth";

// ─── Context ─────────────────────────────────────────────────────────────────

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}

// ─── Provider ────────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // ── Restore session from localStorage ──────────────────────────
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed: AuthUser = JSON.parse(stored);

        // Check if token is still valid (with 60s buffer)
        if (parsed.expiresAt * 1000 > Date.now() + 60_000) {
          setUser(parsed);
        } else {
          // Token expired — clean up
          localStorage.removeItem(STORAGE_KEY);
        }
      }
    } catch {
      localStorage.removeItem(STORAGE_KEY);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // ── Login ──────────────────────────────────────────────────────
  const login = useCallback(async (username: string, password: string) => {
    const { data } = await api.post("/auth/login", { username, password });

    const authUser: AuthUser = {
      username: data.username,
      role: data.role,
      token: data.token,
      expiresAt: data.expires_at,
    };

    localStorage.setItem(STORAGE_KEY, JSON.stringify(authUser));

    // Also set a simple cookie for Next.js middleware (edge runtime)
    // HttpOnly is not possible from client JS, but this cookie is only
    // used for route protection decisions, not as the auth credential itself.
    document.cookie = `packetlens_token=${data.token}; path=/; max-age=${60 * 60 * 24}; SameSite=Strict`;

    setUser(authUser);
  }, []);

  // ── Logout ─────────────────────────────────────────────────────
  const logout = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    document.cookie =
      "packetlens_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT";
    setUser(null);

    // Redirect to login
    if (typeof window !== "undefined") {
      window.location.href = "/login";
    }
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
        token: user?.token ?? null,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
