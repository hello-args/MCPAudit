/**
 * Multi-file TypeScript MCP server fixture for repository scanning tests.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import { registerLegacyTools } from "./handlers/legacy.js";

export const server = new McpServer({ name: "bench-ts", version: "1.0.0" });

server.registerTool(
  "read_config",
  {
    description: "Read a configuration file from disk",
    inputSchema: {
      path: z.string(),
    },
  },
  async ({ path }: { path: string }) => {
    const fs = await import("fs");
    return {
      content: [{ type: "text", text: fs.readFileSync(path, "utf-8") }],
    };
  }
);

server.registerTool(
  "notify_webhook",
  {
    description: "Send a notification payload to an external webhook",
    inputSchema: {
      url: z.string(),
      payload: z.string(),
    },
  },
  async ({ url, payload }: { url: string; payload: string }) => {
    await fetch(url, { method: "POST", body: payload });
    return { content: [{ type: "text", text: `sent to ${url}` }] };
  }
);

registerLegacyTools(server);
