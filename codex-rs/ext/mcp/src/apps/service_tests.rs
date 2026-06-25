use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Instant;

use codex_apps::CodexAppsAccessGuard;
use codex_apps::CodexAppsConnectConfig;
use codex_config::McpServerTransportConfig;
use codex_config::types::AuthKeyringBackendKind;
use codex_config::types::OAuthCredentialsStoreMode;
use codex_core::config::ConfigBuilder;
use pretty_assertions::assert_eq;

use super::CodexAppsConnectionKey;
use super::CodexAppsMcpExtension;
use super::test_support::connector_tool;
use super::test_support::mcp_manager_for_servers;
use super::test_support::test_apps;
use super::test_support::test_apps_with_access_guard;

fn connection_key(label: &str, auth_revision: u64) -> CodexAppsConnectionKey {
    CodexAppsConnectionKey {
        config: CodexAppsConnectConfig::new(
            format!("https://{label}.example"),
            /*product_sku*/ None,
            OAuthCredentialsStoreMode::default(),
            AuthKeyringBackendKind::default(),
        ),
        auth_revision,
    }
}

#[tokio::test]
async fn shutdown_closes_the_current_apps_http_runtime() {
    let service =
        CodexAppsMcpExtension::new_for_tests(codex_login::AuthManager::from_auth_for_testing(
            codex_login::CodexAuth::create_dummy_chatgpt_auth_for_testing(),
        ));
    let apps = test_apps(vec![connector_tool(
        "alpha",
        "Alpha",
        "AlphaPing",
        /*destructive*/ false,
    )])
    .await;
    let server = apps
        .snapshot()
        .effective_mcp_servers()
        .remove("codex_apps__alpha")
        .expect("alpha MCP server");
    let McpServerTransportConfig::StreamableHttp { url, .. } = &server.config().transport else {
        panic!("Apps servers must use streamable HTTP");
    };
    let address = url
        .strip_prefix("http://")
        .and_then(|url| url.split('/').next())
        .expect("loopback MCP address");
    service
        .connection
        .apps_for_key(
            connection_key("config-a", /*auth_revision*/ 7),
            /*refresh*/ false,
            {
                let apps = Arc::clone(&apps);
                move || async move { Ok(apps) }
            },
        )
        .await
        .expect("remember Apps runtime")
        .expect("Apps runtime is current");
    assert!(tokio::net::TcpStream::connect(address).await.is_ok());

    service.shutdown().await;

    assert!(
        service
            .connection
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none()
    );
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn current_connection_is_bounded_while_old_registrations_retain_their_runtime() {
    let service = Arc::new(CodexAppsMcpExtension::new_for_tests(
        codex_login::AuthManager::from_auth_for_testing(
            codex_login::CodexAuth::create_dummy_chatgpt_auth_for_testing(),
        ),
    ));
    let apps_a = test_apps(vec![connector_tool(
        "alpha",
        "Alpha",
        "AlphaPing",
        /*destructive*/ false,
    )])
    .await;
    let weak_apps_a = Arc::downgrade(&apps_a);
    let connected_a = service
        .connection
        .apps_for_key(
            connection_key("config-a", /*auth_revision*/ 7),
            /*refresh*/ false,
            {
                let apps_a = Arc::clone(&apps_a);
                move || async move { Ok(apps_a) }
            },
        )
        .await
        .expect("remember config A")
        .expect("config A revision is current");
    let manager_a = mcp_manager_for_servers(&connected_a.snapshot().effective_mcp_servers()).await;
    drop(connected_a);
    drop(apps_a);
    manager_a
        .call_tool(
            "codex_apps__alpha",
            "ping",
            /*arguments*/ None,
            /*meta*/ None,
        )
        .await
        .expect("config A call before config B");

    let apps_b = test_apps(vec![connector_tool(
        "beta", "Beta", "BetaPing", /*destructive*/ false,
    )])
    .await;
    service
        .connection
        .apps_for_key(
            connection_key("config-b", /*auth_revision*/ 7),
            /*refresh*/ false,
            {
                let apps_b = Arc::clone(&apps_b);
                move || async move { Ok(apps_b) }
            },
        )
        .await
        .expect("remember config B")
        .expect("config B revision is current");

    assert_eq!(
        service
            .connection
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|current| current.key.clone()),
        Some(connection_key("config-b", /*auth_revision*/ 7))
    );
    assert!(
        weak_apps_a.upgrade().is_none(),
        "the service must not retain every CodexApps wrapper"
    );
    manager_a
        .call_tool(
            "codex_apps__alpha",
            "ping",
            /*arguments*/ None,
            /*meta*/ None,
        )
        .await
        .expect("the old manager's runtime owner must retain config A");

    let apps_c = test_apps(vec![connector_tool(
        "gamma",
        "Gamma",
        "GammaPing",
        /*destructive*/ false,
    )])
    .await;
    service
        .connection
        .apps_for_key(
            connection_key("config-c", /*auth_revision*/ 8),
            /*refresh*/ false,
            {
                let apps_c = Arc::clone(&apps_c);
                move || async move { Ok(apps_c) }
            },
        )
        .await
        .expect("remember config C")
        .expect("new auth revision is current");
    let stale = service
        .connection
        .apps_for_key(
            connection_key("stale", /*auth_revision*/ 7),
            /*refresh*/ false,
            || async { anyhow::bail!("a stale auth revision must not start a connection") },
        )
        .await
        .expect("reject stale revision without an internal error");
    assert!(stale.is_none());
    assert_eq!(
        service
            .connection
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|current| current.key.clone()),
        Some(connection_key("config-c", /*auth_revision*/ 8))
    );

    manager_a.shutdown().await;
    service.connection.clear_connected_through(u64::MAX);
    apps_b.shutdown().await;
    apps_c.shutdown().await;
}

#[tokio::test]
async fn direct_snapshot_refreshes_stale_inventory_and_retries_after_last_good_fallback() {
    let codex_home = tempfile::tempdir().expect("temp codex home");
    let config = ConfigBuilder::default()
        .codex_home(codex_home.path().to_path_buf())
        .fallback_cwd(Some(codex_home.path().to_path_buf()))
        .cli_overrides(vec![("features.apps".to_string(), true.into())])
        .build()
        .await
        .expect("load config");
    let service = Arc::new(CodexAppsMcpExtension::new_for_tests(
        codex_login::AuthManager::from_auth_for_testing(
            codex_login::CodexAuth::create_dummy_chatgpt_auth_for_testing(),
        ),
    ));
    let refresh_allowed = Arc::new(AtomicBool::new(true));
    let access_checks = Arc::new(AtomicUsize::new(0));
    let access_guard = CodexAppsAccessGuard::new({
        let refresh_allowed = Arc::clone(&refresh_allowed);
        let access_checks = Arc::clone(&access_checks);
        move || {
            access_checks.fetch_add(1, Ordering::AcqRel);
            refresh_allowed.load(Ordering::Acquire)
        }
    });
    let (apps, _) = test_apps_with_access_guard(
        vec![connector_tool(
            "alpha",
            "Alpha",
            "AlphaPing",
            /*destructive*/ false,
        )],
        access_guard,
    )
    .await;
    let connection_key = service
        .connection
        .connection_key(&config)
        .await
        .expect("eligible Apps connection key");
    service
        .connection
        .apps_for_key(connection_key, /*refresh*/ false, {
            let apps = Arc::clone(&apps);
            move || async move { Ok(apps) }
        })
        .await
        .expect("publish Apps connection")
        .expect("Apps connection is current");
    let server_url = |snapshot: &codex_apps::CodexAppsSnapshot| {
        let server = snapshot
            .effective_mcp_servers()
            .remove("codex_apps__alpha")
            .expect("alpha MCP server");
        let McpServerTransportConfig::StreamableHttp { url, .. } = &server.config().transport
        else {
            panic!("Apps servers must use streamable HTTP");
        };
        url.clone()
    };
    let initial_url = server_url(&apps.snapshot());

    let checks_before_fresh = access_checks.load(Ordering::Acquire);
    let fresh = service
        .snapshot(&config)
        .await
        .expect("read fresh snapshot")
        .expect("fresh Apps snapshot");
    assert_eq!(server_url(&fresh), initial_url);
    assert_eq!(
        access_checks.load(Ordering::Acquire),
        checks_before_fresh,
        "fresh snapshots must not fetch inventory"
    );

    let stale_at = Instant::now() - codex_connectors::CONNECTORS_CACHE_TTL;
    service
        .connection
        .current
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
        .expect("current Apps connection")
        .refreshed_at = Some(stale_at);
    let checks_before_current = access_checks.load(Ordering::Acquire);
    let current = service
        .current_snapshot(&config)
        .await
        .expect("current Apps snapshot");
    assert_eq!(server_url(&current), initial_url);
    assert_eq!(
        access_checks.load(Ordering::Acquire),
        checks_before_current,
        "current_snapshot must remain network-free even when stale"
    );

    let mut callers = Vec::new();
    for _ in 0..8 {
        let service = Arc::clone(&service);
        let config = config.clone();
        callers.push(tokio::spawn(async move { service.snapshot(&config).await }));
    }
    let mut refreshed_urls = Vec::new();
    for caller in callers {
        let refreshed = caller
            .await
            .expect("stale snapshot caller")
            .expect("refresh stale snapshot")
            .expect("refreshed Apps snapshot");
        refreshed_urls.push(server_url(&refreshed));
    }
    let refreshed_url = refreshed_urls[0].clone();
    assert!(refreshed_urls.iter().all(|url| url == &refreshed_url));
    assert_ne!(refreshed_url, initial_url);
    assert_eq!(
        access_checks.load(Ordering::Acquire),
        checks_before_current + 1,
        "concurrent stale readers must coalesce one inventory refresh"
    );
    assert!(
        service
            .connection
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .expect("current Apps connection")
            .refreshed_at
            .is_some_and(|refreshed_at| refreshed_at > stale_at)
    );

    refresh_allowed.store(false, Ordering::Release);
    let failed_stale_at = Instant::now() - codex_connectors::CONNECTORS_CACHE_TTL;
    service
        .connection
        .current
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
        .expect("current Apps connection")
        .refreshed_at = Some(failed_stale_at);
    let checks_before_failure = access_checks.load(Ordering::Acquire);
    let fallback = service
        .snapshot(&config)
        .await
        .expect("stale refresh failure uses last-good snapshot")
        .expect("last-good Apps snapshot");
    assert_eq!(server_url(&fallback), refreshed_url);
    let checks_after_failure = access_checks.load(Ordering::Acquire);
    assert!(checks_after_failure > checks_before_failure);
    assert_eq!(
        service
            .connection
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .expect("current Apps connection")
            .refreshed_at,
        Some(failed_stale_at),
        "failed refresh must not advance freshness"
    );

    let retry_fallback = service
        .snapshot(&config)
        .await
        .expect("subsequent stale refresh failure uses last-good snapshot")
        .expect("last-good Apps snapshot after retry");
    assert_eq!(server_url(&retry_fallback), refreshed_url);
    assert!(access_checks.load(Ordering::Acquire) > checks_after_failure);

    service.shutdown().await;
}

#[tokio::test]
async fn concurrent_connection_misses_are_coalesced() {
    let service = Arc::new(CodexAppsMcpExtension::new_for_tests(
        codex_login::AuthManager::from_auth_for_testing(
            codex_login::CodexAuth::create_dummy_chatgpt_auth_for_testing(),
        ),
    ));
    let apps = test_apps(vec![connector_tool(
        "alpha",
        "Alpha",
        "AlphaPing",
        /*destructive*/ false,
    )])
    .await;
    let connect_count = Arc::new(AtomicUsize::new(0));
    let connect_started = Arc::new(tokio::sync::Notify::new());
    let connect_release = tokio_util::sync::CancellationToken::new();
    let mut callers = Vec::new();
    for _ in 0..8 {
        let service = Arc::clone(&service);
        let apps = Arc::clone(&apps);
        let connect_count = Arc::clone(&connect_count);
        let connect_started = Arc::clone(&connect_started);
        let connect_release = connect_release.clone();
        callers.push(tokio::spawn(async move {
            service
                .connection
                .apps_for_key(
                    connection_key("shared", /*auth_revision*/ 7),
                    /*refresh*/ false,
                    move || async move {
                        connect_count.fetch_add(1, Ordering::AcqRel);
                        connect_started.notify_one();
                        connect_release.cancelled().await;
                        Ok(apps)
                    },
                )
                .await
        }));
    }

    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        connect_started.notified(),
    )
    .await
    .expect("one connection starts");
    connect_release.cancel();
    for caller in callers {
        assert!(
            caller
                .await
                .expect("connection caller task")
                .expect("connection result")
                .is_some()
        );
    }
    assert_eq!(connect_count.load(Ordering::Acquire), 1);

    service.connection.clear_connected_through(u64::MAX);
    apps.shutdown().await;
}

#[tokio::test]
async fn stale_logged_out_observation_cannot_clear_a_newer_connection() {
    let auth_manager = codex_login::AuthManager::from_auth_for_testing(
        codex_login::CodexAuth::create_dummy_chatgpt_auth_for_testing(),
    );
    let service = CodexAppsMcpExtension::new_for_tests(Arc::clone(&auth_manager));
    auth_manager.logout().await.expect("log out test account");
    let (auth, observed_logged_out_revision) = service.connection.current_auth().await;
    assert!(auth.is_none());

    let apps = test_apps(vec![connector_tool(
        "new", "New", "NewPing", /*destructive*/ false,
    )])
    .await;
    let newer_key = connection_key("new-login", observed_logged_out_revision + 1);
    service
        .connection
        .apps_for_key(newer_key.clone(), /*refresh*/ false, {
            let apps = Arc::clone(&apps);
            move || async move { Ok(apps) }
        })
        .await
        .expect("publish newer connection")
        .expect("newer revision is accepted");

    service
        .connection
        .clear_connected_through(observed_logged_out_revision);
    assert_eq!(
        service
            .connection
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|current| current.key.clone()),
        Some(newer_key),
        "cleanup must use the revision paired with the no-auth observation"
    );

    service.connection.clear_connected_through(u64::MAX);
    apps.shutdown().await;
}
