import { createServer, type Server } from "http";
import { type IncomingMessage, type ServerResponse } from "http";
import { URL } from "url";

export interface ProxyConfig {
  proxyPort: number;
  backendUrl: string;
  tenantId: string;
  wafServerUrl: string;
}

export class WafReverseProxy {
  private server: Server | null = null;
  private config: ProxyConfig;

  constructor(config: ProxyConfig) {
    this.config = config;
  }

  /**
   * Start the reverse proxy server
   * Listens on configured port and accepts raw HTTP traffic
   */
  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = createServer(
        async (req: IncomingMessage, res: ServerResponse) => {
          try {
            await this.handleRequest(req, res);
          } catch (error) {
            console.error("WAF proxy error:", error);
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "WAF proxy error" }));
          }
        },
      );

      const proxyHost = process.platform === "win32" ? "127.0.0.1" : "0.0.0.0";
      this.server.listen(this.config.proxyPort, proxyHost, () => {
        console.log(
          `✅ WAF Reverse Proxy listening on port ${this.config.proxyPort}`,
        );
        console.log(`   Backend: ${this.config.backendUrl}`);
        console.log(`   Tenant: ${this.config.tenantId}`);
        resolve();
      });

      this.server.on("error", (error) => {
        console.error("WAF proxy server error:", error);
        reject(error);
      });
    });
  }

  /**
   * Stop the proxy server
   */
  stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          console.log("✅ WAF Reverse Proxy stopped");
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  /**
   * Handle incoming HTTP request
   * 1. Collect request body
   * 2. Send to WAF for analysis
   * 3. If blocked, return 403
   * 4. If allowed, forward to backend
   */
  private async handleRequest(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    // Log incoming request
    console.log(
      `[WAF Proxy] ${req.method} ${req.url} from ${req.socket.remoteAddress}`,
    );

    // Collect request body
    const requestBody = await this.collectBody(req);

    // Build WAF request from raw HTTP
    const wafRequest = {
      method: req.method || "GET",
      path: req.url || "/",
      query: this.parseQueryString(req.url || ""),
      headers: req.headers,
      body: requestBody,
      clientIp: req.socket.remoteAddress,
      timestamp: new Date().toISOString(),
    };

    // Send to WAF for analysis
    console.log(`[WAF Proxy] Analyzing request with WAF...`);
    const wafResponse = await fetch(
      `${this.config.wafServerUrl}/api/waf/ingress`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tenantId: this.config.tenantId,
          request: wafRequest,
        }),
      },
    );

    const wafAnalysis = await wafResponse.json();
    console.log(
      `[WAF Proxy] WAF Decision: ${wafAnalysis.action} (score: ${wafAnalysis.score})`,
    );

    // Check WAF decision
    if (wafAnalysis.action === "block") {
      console.log(`[WAF Proxy] ❌ BLOCKED - Returning 403`);
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Blocked by WAF",
          score: wafAnalysis.score,
          riskLevel: wafAnalysis.riskLevel,
          matches: wafAnalysis.matchCount,
          requestId: wafAnalysis.requestId,
        }),
      );
      return;
    }

    if (wafAnalysis.action === "challenge") {
      console.log(`[WAF Proxy] ⚠️  CHALLENGE - Returning 429`);
      res.writeHead(429, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Challenge required",
          requestId: wafAnalysis.requestId,
        }),
      );
      return;
    }

    // Request passed WAF - forward to backend
    console.log(`[WAF Proxy] ✅ ALLOWED - Forwarding to backend`);
    await this.forwardToBackend(req, res, requestBody, wafAnalysis.requestId);
  }

  /**
   * Collect request body from stream
   */
  private collectBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk.toString();
      });
      req.on("end", () => {
        resolve(body);
      });
      req.on("error", reject);
    });
  }

  /**
   * Parse query string from URL
   */
  private parseQueryString(url: string): Record<string, any> {
    const urlObj = new URL(url, "http://dummy");
    const query: Record<string, any> = {};
    urlObj.searchParams.forEach((value, key) => {
      query[key] = value;
    });
    return query;
  }

  /**
   * Forward request to backend server
   */
  private async forwardToBackend(
    req: IncomingMessage,
    res: ServerResponse,
    body: string,
    requestId: string,
  ): Promise<void> {
    try {
      const url = new URL(req.url || "/", this.config.backendUrl);

      const headers: Record<string, string> = {
        "X-WAF-Request-ID": requestId,
        "X-Forwarded-For": req.socket.remoteAddress || "",
        "X-Forwarded-Proto": "http",
        host: new URL(this.config.backendUrl).host,
        connection: "close",
      };

      // Copy headers from request, filtering out problematic ones
      Object.entries(req.headers).forEach(([key, value]) => {
        if (
          typeof value === "string" &&
          !["host", "connection"].includes(key.toLowerCase())
        ) {
          headers[key] = value;
        }
      });

      const backendReq = await fetch(url.toString(), {
        method: req.method || "GET",
        headers,
        body: req.method !== "GET" && req.method !== "HEAD" ? body : undefined,
      });

      // Copy backend response headers and status
      const backendHeaders = Object.fromEntries(backendReq.headers);
      delete (backendHeaders as any)["transfer-encoding"];
      delete (backendHeaders as any)["content-encoding"];

      res.writeHead(backendReq.status, backendHeaders);

      // Stream backend response body
      const backendBody = await backendReq.text();
      res.end(backendBody);

      console.log(`[WAF Proxy] ✅ Response forwarded (${backendReq.status})`);
    } catch (error) {
      console.error("[WAF Proxy] Backend forwarding error:", error);
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Bad Gateway",
          message: "Failed to forward request to backend",
        }),
      );
    }
  }
}

/**
 * Start WAF reverse proxy (if enabled)
 */
export async function startWafProxy(): Promise<WafReverseProxy | null> {
  const proxyPort = process.env.WAF_PROXY_PORT
    ? parseInt(process.env.WAF_PROXY_PORT, 10)
    : null;
  const backendUrl = process.env.WAF_PROXY_BACKEND;
  const tenantId = process.env.WAF_PROXY_TENANT_ID;

  if (!proxyPort || !backendUrl || !tenantId) {
    console.log(
      "ℹ️  WAF Reverse Proxy not configured (set WAF_PROXY_PORT, WAF_PROXY_BACKEND, WAF_PROXY_TENANT_ID)",
    );
    return null;
  }

  const proxy = new WafReverseProxy({
    proxyPort,
    backendUrl,
    tenantId,
    wafServerUrl: process.env.WAF_SERVER_URL || "http://localhost:5000",
  });

  await proxy.start();
  return proxy;
}
