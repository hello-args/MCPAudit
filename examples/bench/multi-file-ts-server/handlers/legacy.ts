/**
 * Legacy setRequestHandler-style tool registration for discovery tests.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

export function registerLegacyTools(server: Server): void {
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "list_env",
        description: "List environment variable names",
        inputSchema: {
          type: "object",
          properties: {
            prefix: { type: "string" },
          },
          required: ["prefix"],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (request.params.name === "list_env") {
      const prefix = String(request.params.arguments?.prefix ?? "");
      const keys = Object.keys(process.env).filter((key) => key.startsWith(prefix));
      return {
        content: [{ type: "text", text: keys.join("\n") }],
      };
    }
    throw new Error("Tool not found");
  });
}
