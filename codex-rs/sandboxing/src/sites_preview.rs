/// Browser-visible TCP port reserved for Sites local previews.
pub const SITES_PREVIEW_PORT: u16 = 4173;

/// Environment variable carrying exec-server's inherited Sites preview listener fd.
pub const SITES_PREVIEW_LISTENER_FD_ENV_VAR: &str = "CODEX_SITES_PREVIEW_LISTENER_FD";
