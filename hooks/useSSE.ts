import { useEffect, useRef, useState, useCallback } from "react";

interface SSEMessage {
  type: string;
  data: any;
}

export function useSSE(streamPath: string = "/api/traffic/stream") {
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<SSEMessage | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const messageHandlersRef = useRef<Map<string, Set<(data: any) => void>>>(new Map());
  const mountedRef = useRef(true);

  const disconnect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setIsConnected(false);
  }, []);

  const subscribe = useCallback((type: string, handler: (data: any) => void) => {
    if (!messageHandlersRef.current.has(type)) {
      messageHandlersRef.current.set(type, new Set());
    }
    messageHandlersRef.current.get(type)!.add(handler);

    return () => {
      messageHandlersRef.current.get(type)?.delete(handler);
    };
  }, []);

  useEffect(() => {
    if (!streamPath || !mountedRef.current) return;

    const protocol = window.location.protocol === "https:" ? "https:" : "http:";
    const sseUrl = `${protocol}//${window.location.host}${streamPath}`;

    try {
      // EventSource with credentials to send cookies for authentication
      const eventSource = new EventSource(sseUrl, { withCredentials: true });
      let connectionTimeout: NodeJS.Timeout;

      eventSource.onopen = () => {
        if (mountedRef.current) {
          setIsConnected(true);
          console.log("✅ SSE connected");
        }
        // Clear timeout on successful connection
        clearTimeout(connectionTimeout);
      };

      // Set connection timeout - if no onopen within 5 seconds, mark as connected anyway
      connectionTimeout = setTimeout(() => {
        if (mountedRef.current && eventSourceRef.current === eventSource) {
          setIsConnected(true);
          console.log("✅ SSE connection established (timeout fallback)");
        }
      }, 5000);

      // Handle keep-alive messages to detect if connection is alive
      eventSource.addEventListener("message", (event: any) => {
        if (event.data === "keep-alive" || !event.data) {
          if (mountedRef.current && eventSourceRef.current === eventSource) {
            setIsConnected(true);
          }
        }
      });

      // Handle typed events (event: request, event: alert, etc.)
      eventSource.addEventListener("request", (event: any) => {
        if (!mountedRef.current) return;
        try {
          const data = JSON.parse(event.data);
          setLastMessage({ type: "request", data });
          setIsConnected(true); // Mark connected when receiving events
          const handlers = messageHandlersRef.current.get("request");
          if (handlers) {
            handlers.forEach((handler) => handler(data));
          }
        } catch (err) {
          console.error("Failed to parse SSE request event:", err);
        }
      });

      eventSource.addEventListener("alert", (event: any) => {
        if (!mountedRef.current) return;
        try {
          const data = JSON.parse(event.data);
          setLastMessage({ type: "alert", data });
          setIsConnected(true); // Mark connected when receiving events
          const handlers = messageHandlersRef.current.get("alert");
          if (handlers) {
            handlers.forEach((handler) => handler(data));
          }
        } catch (err) {
          console.error("Failed to parse SSE alert event:", err);
        }
      });

      eventSource.onerror = (error) => {
        if (mountedRef.current) {
          console.error("❌ SSE error:", error);
          setIsConnected(false);
          eventSource.close();
        }
        clearTimeout(connectionTimeout);
      };

      eventSourceRef.current = eventSource;
    } catch (err) {
      console.error("Failed to create EventSource:", err);
    }

    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
    };
  }, [streamPath]);

  useEffect(() => {
    return () => {
      mountedRef.current = false;
    };
  }, []);

  return {
    isConnected,
    lastMessage,
    subscribe,
    disconnect,
  };
}
