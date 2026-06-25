use std::sync::Arc;

use codex_core::config::Config;
use codex_extension_api::ExtensionRegistryBuilder;

mod apps;
mod executor_plugin;

pub use apps::CodexAppsMcpExtension;

/// Installs a process-shared Apps service as an MCP contributor.
pub fn install(
    builder: &mut ExtensionRegistryBuilder<Config>,
    service: Arc<CodexAppsMcpExtension>,
) {
    builder.thread_data_initializer(service.clone());
    builder.mcp_server_contributor(service.clone());
    builder.plugin_install_verifier(service.clone());
    builder.prompt_contributor(service.clone());
    builder.turn_input_contributor(service.clone());
    builder.tool_lifecycle_contributor(service.clone());
    builder.turn_item_contributor(service);
}

/// Installs selected executor-plugin MCP metadata before the Apps contributor that consumes it.
pub fn install_with_executor_plugins(
    builder: &mut ExtensionRegistryBuilder<Config>,
    service: Arc<CodexAppsMcpExtension>,
    environment_manager: Arc<codex_exec_server::EnvironmentManager>,
) {
    install_executor_plugins(builder, environment_manager);
    install(builder, service);
}

/// Installs discovery for MCP servers declared by thread-selected executor plugins.
pub fn install_executor_plugins(
    builder: &mut ExtensionRegistryBuilder<Config>,
    environment_manager: Arc<codex_exec_server::EnvironmentManager>,
) {
    builder.mcp_server_contributor(Arc::new(
        executor_plugin::SelectedExecutorPluginMcpContributor::new(environment_manager),
    ));
}
