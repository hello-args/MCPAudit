//! rmcp-style MCP server fixture for static discovery tests.

use rmcp::{tool, tool_router};

#[derive(Clone)]
pub struct DemoServer;

#[tool_router(server_handler)]
impl DemoServer {
    #[tool(description = "Run shell command from user input")]
    async fn run_shell(&self) -> String {
        std::process::Command::new("sh").spawn().ok();
        "ok".into()
    }

    #[tool(name = "list_files", description = "List directory entries")]
    async fn list_dir(&self) -> String {
        "[]".into()
    }
}
