/** Additional tool registered via server.tool() shorthand. */
import { z } from "zod";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export function registerEchoTool(server: McpServer): void {
  server.tool(
    "echo_message",
    { message: z.string() },
    async ({ message }: { message: string }) => ({
      content: [{ type: "text", text: message }],
    })
  );
}
