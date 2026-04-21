import { useEffect, useRef, useState } from "react";
import { getAuthToken } from "@/services/api";

export type SSEStatus = "connecting" | "connected" | "disconnected" | "error";

interface UseSSEOptions<T> {
  /** Full URL to the SSE endpoint */
  url: string;
  /** SSE event name to listen for (e.g., "incident") */
  event: string;
  /** Callback fired for each incoming event */
  onMessage: (data: T) => void;
  /** Set to false to pause the connection */
  enabled?: boolean;
}

/**
 * Custom hook for Server-Sent Events with JWT auth and auto-reconnection.
 *
 * Since the native EventSource API does not support custom headers,
 * the JWT token is appended as a `?token=` query parameter.
 * The Go API middleware checks this fallback when no Authorization header is present.
 *
 * Cleans up on unmount to prevent goroutine/memory leaks.
 */
export function useSSE<T>({
  url,
  event,
  onMessage,
  enabled = true,
}: UseSSEOptions<T>): SSEStatus {
  const [status, setStatus] = useState<SSEStatus>("disconnected");

  // Use a ref for the callback so we don't re-create the EventSource
  // when the callback identity changes (common with inline arrow functions).
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    if (!enabled) {
      setStatus("disconnected");
      return;
    }

    // ── Build authenticated URL ──────────────────────────────────
    const token = getAuthToken();
    if (!token) {
      setStatus("error");
      return;
    }

    const separator = url.includes("?") ? "&" : "?";
    const authedUrl = `${url}${separator}token=${encodeURIComponent(token)}`;

    setStatus("connecting");

    const es = new EventSource(authedUrl);

    // ── Connected ────────────────────────────────────────────────
    es.addEventListener("connected", () => {
      setStatus("connected");
    });

    // ── Data events ──────────────────────────────────────────────
    es.addEventListener(event, (e: MessageEvent) => {
      try {
        const parsed = JSON.parse(e.data) as T;
        onMessageRef.current(parsed);
      } catch (err) {
        console.error("[useSSE] Failed to parse event data:", err);
      }
    });

    // ── Connection opened ────────────────────────────────────────
    es.onopen = () => {
      setStatus("connected");
    };

    // ── Error / auto-reconnect ───────────────────────────────────
    es.onerror = () => {
      if (es.readyState === EventSource.CONNECTING) {
        setStatus("connecting");
      } else {
        setStatus("error");
      }
    };

    // ── Cleanup on unmount or dependency change ──────────────────
    return () => {
      es.close();
      setStatus("disconnected");
    };
  }, [url, event, enabled]);

  return status;
}
