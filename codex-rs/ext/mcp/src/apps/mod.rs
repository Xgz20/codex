use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::PoisonError;
use std::sync::RwLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Instant;

use codex_analytics::AnalyticsEventsClient;
use codex_apps::CodexApps;
use codex_apps::CodexAppsConnectConfig;
use codex_apps::CodexAppsSnapshot;
use codex_connectors::CONNECTORS_CACHE_TTL;
use codex_connectors::ConnectorSnapshot;
use codex_core::config::Config;
use codex_core_plugins::PluginsManager;
use codex_login::AuthManager;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use self::config::apps_connect_config;
use self::config::apps_inventory_eligible;
use self::config::auth_revision_access_guard;
use self::config::current_auth_revision;

mod analytics;
mod config;
mod contributor;
mod install_verification;
mod policy;
mod presentation;

#[cfg(test)]
mod test_support;
#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CodexAppsConnectionKey {
    config: CodexAppsConnectConfig,
    auth_revision: u64,
}

struct ConnectedCodexApps {
    key: CodexAppsConnectionKey,
    apps: Arc<CodexApps>,
    refreshed_at: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AppsRefreshRequirement {
    None,
    EnsureLive,
    Refresh,
}

struct AppsConnectionService {
    auth_manager: Arc<AuthManager>,
    environment_manager: Arc<codex_exec_server::EnvironmentManager>,
    current: RwLock<Option<ConnectedCodexApps>>,
    connect: Mutex<()>,
    publication_revision: Arc<AtomicU64>,
    publication_reservations: StdMutex<Vec<CodexAppsConnectionKey>>,
    background_initializations: StdMutex<Vec<CodexAppsConnectionKey>>,
    shutdown: CancellationToken,
}

struct AppsBackgroundInitialization {
    connection: Arc<AppsConnectionService>,
    key: CodexAppsConnectionKey,
}

struct AppsPublicationReservation {
    connection: Arc<AppsConnectionService>,
    key: CodexAppsConnectionKey,
}

/// Contributes connector-scoped HTTP MCP servers from one shared Apps inventory owner.
pub struct CodexAppsMcpExtension {
    connection: Arc<AppsConnectionService>,
    initialization_tasks: StdMutex<JoinSet<()>>,
    plugins_manager: Arc<PluginsManager>,
    analytics_events_client: AnalyticsEventsClient,
}

impl CodexAppsMcpExtension {
    #[cfg(test)]
    fn new_for_tests(auth_manager: Arc<AuthManager>) -> Self {
        let codex_home = tempfile::tempdir().expect("temporary Codex home").keep();
        Self::new(
            auth_manager,
            Arc::new(codex_exec_server::EnvironmentManager::without_environments()),
            Arc::new(PluginsManager::new(codex_home)),
        )
    }

    pub fn new(
        auth_manager: Arc<AuthManager>,
        environment_manager: Arc<codex_exec_server::EnvironmentManager>,
        plugins_manager: Arc<PluginsManager>,
    ) -> Self {
        Self::new_with_analytics(
            auth_manager,
            environment_manager,
            plugins_manager,
            AnalyticsEventsClient::disabled(),
        )
    }

    pub fn new_with_analytics(
        auth_manager: Arc<AuthManager>,
        environment_manager: Arc<codex_exec_server::EnvironmentManager>,
        plugins_manager: Arc<PluginsManager>,
        analytics_events_client: AnalyticsEventsClient,
    ) -> Self {
        let connection = Arc::new(AppsConnectionService {
            auth_manager,
            environment_manager,
            current: RwLock::new(None),
            connect: Mutex::new(()),
            publication_revision: Arc::new(AtomicU64::new(0)),
            publication_reservations: StdMutex::new(Vec::new()),
            background_initializations: StdMutex::new(Vec::new()),
            shutdown: CancellationToken::new(),
        });
        Self {
            connection,
            initialization_tasks: StdMutex::new(JoinSet::new()),
            plugins_manager,
            analytics_events_client,
        }
    }

    async fn plugin_connector_snapshot(&self, config: &Config) -> ConnectorSnapshot {
        let loaded_plugins = self
            .plugins_manager
            .plugins_for_config(&config.plugins_config_input())
            .await;
        ConnectorSnapshot::from_plugin_capability_summaries(loaded_plugins.capability_summaries())
    }

    /// Returns the current connector inventory when Apps is eligible for this config.
    pub async fn snapshot(&self, config: &Config) -> anyhow::Result<Option<CodexAppsSnapshot>> {
        if !apps_inventory_eligible(config) {
            return Ok(None);
        }
        let Some((key, apps)) = self
            .connection
            .apps_for_config(config, /*refresh*/ false)
            .await?
        else {
            return Ok(None);
        };
        if let Err(error) = self.connection.refresh_if_stale(&key, &apps).await {
            tracing::warn!(%error, "failed to refresh stale Codex Apps inventory; using last-good snapshot");
        }
        Ok(Some(apps.snapshot()))
    }

    /// Returns the first available connector inventory without waiting for cached data to refresh.
    pub async fn snapshot_allowing_cached(
        &self,
        config: &Config,
    ) -> anyhow::Result<Option<CodexAppsSnapshot>> {
        if !apps_inventory_eligible(config) {
            return Ok(None);
        }
        Ok(self
            .connection
            .apps_for_config(config, /*refresh*/ false)
            .await?
            .map(|(_, apps)| apps.snapshot()))
    }

    /// Returns the already-connected snapshot without performing network discovery.
    pub async fn current_snapshot(&self, config: &Config) -> Option<CodexAppsSnapshot> {
        if !apps_inventory_eligible(config) {
            return None;
        }
        self.connection
            .current_snapshot_with_key(config)
            .await
            .map(|(_, snapshot)| snapshot)
    }

    fn initialize_in_background(
        &self,
        config: Config,
        connection_key: CodexAppsConnectionKey,
        thread_state: Option<(Arc<presentation::AppsThreadState>, u64)>,
    ) {
        if self.connection.shutdown.is_cancelled() {
            return;
        }
        let Some(background_initialization) = self
            .connection
            .begin_background_initialization(connection_key.clone())
        else {
            // Another thread can enter Discovering after the active attempt's publication was
            // already observed. Publish that new waiter once so its next boundary joins the
            // shared connection. Global contributors have no thread state to strand and must not
            // repeatedly advance the revision while discovery is pending.
            if thread_state.is_some() {
                self.connection
                    .publication_revision
                    .fetch_add(1, Ordering::AcqRel);
            }
            return;
        };
        // Reserve one publication before launching so every safe boundary observes the pending
        // discovery. A successful background connection consumes this revision; only failures
        // publish again so the next boundary retries.
        let publication_reservation = self.connection.reserve_publication(connection_key);
        self.connection
            .publication_revision
            .fetch_add(1, Ordering::AcqRel);
        let connection = Arc::clone(&self.connection);
        let task = async move {
            let result = tokio::select! {
                _ = connection.shutdown.cancelled() => Ok(None),
                result = connection.apps_for_config_with_reserved_publication(
                    &config,
                    /*refresh*/ false,
                    publication_reservation,
                ) => result,
            };
            drop(background_initialization);
            match result {
                Ok(Some((connection_key, apps))) => {
                    if let Some((state, state_revision)) = thread_state {
                        let snapshot = apps.snapshot();
                        state.replace_apps_if_revision(
                            state_revision,
                            connection_key,
                            apps,
                            snapshot,
                            &config,
                        );
                    }
                }
                Ok(None) => {
                    if let Some((state, state_revision)) = thread_state {
                        state.clear_if_revision(state_revision, &config);
                    }
                }
                Err(error) => {
                    // Publish the failed attempt only after releasing the single-flight gate. The
                    // host will resolve the contributor again at its next safe boundary, where a
                    // new background attempt can start without turning Apps availability into a
                    // startup dependency.
                    connection
                        .publication_revision
                        .fetch_add(1, Ordering::AcqRel);
                    tracing::warn!(%error, "failed to initialize Codex Apps MCP");
                }
            }
        };
        self.spawn_background_task(task);
    }

    fn refresh_in_background(&self, connection_key: CodexAppsConnectionKey, apps: Arc<CodexApps>) {
        if self.connection.shutdown.is_cancelled()
            || self.connection.refresh_requirement(&connection_key, &apps)
                == AppsRefreshRequirement::None
        {
            return;
        }
        let Some(background_refresh) = self
            .connection
            .begin_background_initialization(connection_key.clone())
        else {
            return;
        };
        let connection = Arc::clone(&self.connection);
        let task = async move {
            let result = tokio::select! {
                _ = connection.shutdown.cancelled() => Ok(()),
                result = connection.refresh_if_stale(&connection_key, &apps) => result,
            };
            drop(background_refresh);
            if let Err(error) = result {
                connection
                    .publication_revision
                    .fetch_add(1, Ordering::AcqRel);
                tracing::warn!(%error, "failed to refresh stale Codex Apps MCP");
            }
        };
        self.spawn_background_task(task);
    }

    fn spawn_background_task(&self, task: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = self
            .initialization_tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        while let Some(result) = tasks.try_join_next() {
            log_initialization_join_result(result);
        }
        if !self.connection.shutdown.is_cancelled() {
            tasks.spawn(task);
        }
    }

    /// Prevents new background initialization and cancels any initialization in progress.
    pub fn begin_shutdown(&self) {
        self.connection.shutdown.cancel();
    }

    /// Cancels and joins background initialization, then stops the connected Apps runtime.
    pub async fn shutdown(&self) {
        self.begin_shutdown();
        let mut tasks = {
            let mut tasks = self
                .initialization_tasks
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            std::mem::replace(&mut *tasks, JoinSet::new())
        };
        while let Some(result) = tasks.join_next().await {
            log_initialization_join_result(result);
        }
        let connected = self
            .connection
            .current
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(connected) = connected {
            connected.apps.shutdown().await;
        }
    }

    /// Refreshes and returns the connector inventory when Apps is eligible for this config.
    pub async fn refresh_snapshot(
        &self,
        config: &Config,
    ) -> anyhow::Result<Option<CodexAppsSnapshot>> {
        if !apps_inventory_eligible(config) {
            return Ok(None);
        }
        Ok(self
            .connection
            .apps_for_config(config, /*refresh*/ true)
            .await?
            .map(|(_, apps)| apps.snapshot()))
    }
}

impl AppsConnectionService {
    async fn connection_key(&self, config: &Config) -> Option<CodexAppsConnectionKey> {
        if self.shutdown.is_cancelled() {
            return None;
        }
        let (auth, auth_revision) = self.current_auth().await;
        let Some(auth) = auth else {
            self.clear_connected_through(auth_revision);
            return None;
        };
        Some(CodexAppsConnectionKey {
            config: apps_connect_config(config, &auth),
            auth_revision,
        })
    }

    async fn current_snapshot_with_key(
        &self,
        config: &Config,
    ) -> Option<(CodexAppsConnectionKey, CodexAppsSnapshot)> {
        let key = self.connection_key(config).await?;
        self.current_apps_for_key(&key)
            .map(|apps| (key, apps.snapshot()))
    }

    fn current_apps_for_key(&self, key: &CodexAppsConnectionKey) -> Option<Arc<CodexApps>> {
        let current = self.current.read().unwrap_or_else(PoisonError::into_inner);
        current
            .as_ref()
            .filter(|connected| &connected.key == key)
            .map(|connected| Arc::clone(&connected.apps))
    }

    async fn refresh_if_stale(
        &self,
        key: &CodexAppsConnectionKey,
        apps: &Arc<CodexApps>,
    ) -> anyhow::Result<()> {
        if self.refresh_requirement(key, apps) == AppsRefreshRequirement::None {
            return Ok(());
        }

        let _refresh = self.connect.lock().await;
        match self.refresh_requirement(key, apps) {
            AppsRefreshRequirement::None => return Ok(()),
            AppsRefreshRequirement::EnsureLive => {
                apps.ensure_live().await?;
            }
            AppsRefreshRequirement::Refresh => {
                apps.refresh().await?;
            }
        }
        self.mark_refreshed(key, apps);
        Ok(())
    }

    fn refresh_requirement(
        &self,
        key: &CodexAppsConnectionKey,
        apps: &Arc<CodexApps>,
    ) -> AppsRefreshRequirement {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|connected| connected.key == *key && Arc::ptr_eq(&connected.apps, apps))
            .map_or(AppsRefreshRequirement::None, |connected| {
                match connected.refreshed_at {
                    None => AppsRefreshRequirement::EnsureLive,
                    Some(refreshed_at) if refreshed_at.elapsed() >= CONNECTORS_CACHE_TTL => {
                        AppsRefreshRequirement::Refresh
                    }
                    Some(_) => AppsRefreshRequirement::None,
                }
            })
    }

    fn mark_refreshed(&self, key: &CodexAppsConnectionKey, apps: &Arc<CodexApps>) {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(connected) = current.as_mut()
            && connected.key == *key
            && Arc::ptr_eq(&connected.apps, apps)
        {
            connected.refreshed_at = Some(Instant::now());
        }
    }

    async fn current_auth(&self) -> (Option<codex_login::CodexAuth>, u64) {
        let (auth, revision) = self.auth_manager.auth_with_revision().await;
        (
            auth.filter(codex_login::CodexAuth::uses_codex_backend),
            revision,
        )
    }

    async fn apps_for_config(
        self: &Arc<Self>,
        config: &Config,
        refresh: bool,
    ) -> anyhow::Result<Option<(CodexAppsConnectionKey, Arc<CodexApps>)>> {
        self.apps_for_config_inner(config, refresh, /*publication_reservation*/ None)
            .await
    }

    async fn apps_for_config_with_reserved_publication(
        self: &Arc<Self>,
        config: &Config,
        refresh: bool,
        mut publication_reservation: AppsPublicationReservation,
    ) -> anyhow::Result<Option<(CodexAppsConnectionKey, Arc<CodexApps>)>> {
        self.apps_for_config_inner(config, refresh, Some(&mut publication_reservation))
            .await
    }

    async fn apps_for_config_inner(
        self: &Arc<Self>,
        config: &Config,
        refresh: bool,
        mut publication_reservation: Option<&mut AppsPublicationReservation>,
    ) -> anyhow::Result<Option<(CodexAppsConnectionKey, Arc<CodexApps>)>> {
        loop {
            let (auth, auth_revision) = self.current_auth().await;
            let Some(auth) = auth else {
                self.clear_connected_through(auth_revision);
                return Ok(None);
            };

            let connect_config = apps_connect_config(config, &auth);
            let key = CodexAppsConnectionKey {
                config: connect_config.clone(),
                auth_revision,
            };
            if let Some(reservation) = publication_reservation.as_deref_mut() {
                reservation.retarget(key.clone());
            }
            let auth_provider = codex_model_provider::auth_provider_from_auth(&auth);
            let access_guard = auth_revision_access_guard(&self.auth_manager, auth_revision);
            let environment_manager = Arc::clone(&self.environment_manager);
            let publication_revision = Arc::clone(&self.publication_revision);
            let apps = tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => return Ok(None),
                apps = self.apps_for_key(key.clone(), refresh, move || async move {
                    let on_change: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                        publication_revision.fetch_add(1, Ordering::AcqRel);
                    });
                    Ok(Arc::new(
                        CodexApps::connect_with_environment(
                            &connect_config,
                            auth_provider,
                            environment_manager,
                            on_change,
                            access_guard,
                        )
                        .await?,
                    ))
                }) => apps,
            };
            if current_auth_revision(&self.auth_manager) != auth_revision {
                continue;
            }
            let Some(apps) = apps? else {
                continue;
            };
            return Ok(Some((key, apps)));
        }
    }

    async fn apps_for_key<F, Fut>(
        &self,
        key: CodexAppsConnectionKey,
        refresh: bool,
        connect: F,
    ) -> anyhow::Result<Option<Arc<CodexApps>>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = anyhow::Result<Arc<CodexApps>>>,
    {
        let existing = {
            let current = self.current.read().unwrap_or_else(PoisonError::into_inner);
            if current
                .as_ref()
                .is_some_and(|current| current.key.auth_revision > key.auth_revision)
            {
                return Ok(None);
            }
            current
                .as_ref()
                .filter(|current| current.key == key)
                .map(|current| Arc::clone(&current.apps))
        };
        if let Some(apps) = existing {
            if refresh {
                self.refresh_existing(&key, &apps).await?;
            }
            return Ok(Some(apps));
        }

        // Serialize cold setup without locking the published snapshot. Contributors can continue
        // to use the process-current generation while direct callers await a replacement.
        let _connect = self.connect.lock().await;
        let existing = {
            let current = self.current.read().unwrap_or_else(PoisonError::into_inner);
            if current
                .as_ref()
                .is_some_and(|current| current.key.auth_revision > key.auth_revision)
            {
                return Ok(None);
            }
            current
                .as_ref()
                .filter(|current| current.key == key)
                .map(|current| Arc::clone(&current.apps))
        };
        if let Some(existing) = existing {
            if refresh {
                self.refresh_existing(&key, &existing).await?;
            }
            return Ok(Some(existing));
        }
        let apps = connect().await?;
        if refresh {
            apps.ensure_live().await?;
        }
        let publication_is_reserved = self.publication_is_reserved(&key);
        let refreshed_at = apps.snapshot().is_live_inventory().then(Instant::now);
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Some(ConnectedCodexApps {
            key,
            apps: Arc::clone(&apps),
            refreshed_at,
        });
        if !publication_is_reserved {
            self.publication_revision.fetch_add(1, Ordering::AcqRel);
        }
        Ok(Some(apps))
    }

    async fn refresh_existing(
        &self,
        key: &CodexAppsConnectionKey,
        apps: &Arc<CodexApps>,
    ) -> anyhow::Result<()> {
        if apps.snapshot().is_live_inventory() {
            apps.refresh().await?;
        } else {
            apps.ensure_live().await?;
        }
        self.mark_refreshed(key, apps);
        Ok(())
    }

    fn reserve_publication(
        self: &Arc<Self>,
        key: CodexAppsConnectionKey,
    ) -> AppsPublicationReservation {
        self.publication_reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(key.clone());
        AppsPublicationReservation {
            connection: Arc::clone(self),
            key,
        }
    }

    fn publication_is_reserved(&self, key: &CodexAppsConnectionKey) -> bool {
        self.publication_reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|reserved| reserved == key)
    }

    fn begin_background_initialization(
        self: &Arc<Self>,
        key: CodexAppsConnectionKey,
    ) -> Option<AppsBackgroundInitialization> {
        let mut initializations = self
            .background_initializations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if initializations.contains(&key) {
            return None;
        }
        initializations.push(key.clone());
        Some(AppsBackgroundInitialization {
            connection: Arc::clone(self),
            key,
        })
    }

    #[cfg(test)]
    fn background_initialization_is_active(&self) -> bool {
        !self
            .background_initializations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }

    #[cfg(test)]
    fn background_initialization_is_active_for(&self, key: &CodexAppsConnectionKey) -> bool {
        self.background_initializations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(key)
    }

    fn clear_connected_through(&self, auth_revision: u64) {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        if current
            .as_ref()
            .is_some_and(|current| current.key.auth_revision <= auth_revision)
        {
            *current = None;
        }
    }
}

impl Drop for AppsBackgroundInitialization {
    fn drop(&mut self) {
        let mut initializations = self
            .connection
            .background_initializations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = initializations
            .iter()
            .position(|initialization| initialization == &self.key)
        {
            initializations.swap_remove(index);
        }
    }
}

impl AppsPublicationReservation {
    fn retarget(&mut self, key: CodexAppsConnectionKey) {
        if self.key == key {
            return;
        }
        let mut reservations = self
            .connection
            .publication_reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = reservations
            .iter()
            .position(|reserved| reserved == &self.key)
        {
            reservations.swap_remove(index);
        }
        reservations.push(key.clone());
        self.key = key;
    }
}

impl Drop for AppsPublicationReservation {
    fn drop(&mut self) {
        let mut reservations = self
            .connection
            .publication_reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = reservations
            .iter()
            .position(|reserved| reserved == &self.key)
        {
            reservations.swap_remove(index);
        }
    }
}

impl Drop for CodexAppsMcpExtension {
    fn drop(&mut self) {
        self.begin_shutdown();
    }
}

fn log_initialization_join_result(result: Result<(), tokio::task::JoinError>) {
    if let Err(error) = result
        && !error.is_cancelled()
    {
        tracing::warn!(%error, "Codex Apps background initialization task failed");
    }
}
