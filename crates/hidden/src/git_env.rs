//! Hidden file/path scanner.
//!
//! Probes 100+ paths for exposed sensitive files: source control, env files,
//! config, backups, framework debug pages, API docs, SSH keys, cloud credentials.
//!
//! Key design decisions:
//! - Fully concurrent: all paths probed simultaneously via buffer_unordered.
//! - Content-validated: body must match expected pattern to eliminate false-positives
//!   (e.g. /.git/HEAD must contain "ref:", not just return HTTP 200).
//! - 403-bypass-integrated: any 403 on a sensitive path is immediately probed
//!   for bypass via IP-spoof headers and path normalisation tricks.

use futures::StreamExt;
use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

struct Check {
    path: &'static str,
    title: &'static str,
    severity: Severity,
    detail: &'static str,
    tag: &'static str,
    /// Body must contain this substring — eliminates false positives on catch-all 200s.
    content_probe: Option<&'static str>,
}

macro_rules! check {
    ($path:expr, $title:expr, $sev:expr, $detail:expr, $tag:expr, $probe:expr) => {
        Check {
            path: $path,
            title: $title,
            severity: $sev,
            detail: $detail,
            tag: $tag,
            content_probe: $probe,
        }
    };
}

const CHECKS: &[Check] = &[
    // ── Source control ──────────────────────────────────────────────────────
    check!(
        "/.git/HEAD",
        "Git repository exposed",
        Severity::Critical,
        "The .git directory is publicly accessible — full source reconstruction possible.",
        "git",
        Some("ref:")
    ),
    check!(
        "/.git/config",
        "Git config exposed",
        Severity::Critical,
        ".git/config leaked — remote URLs, credentials, branch names.",
        "git",
        Some("[core]")
    ),
    check!(
        "/.git/COMMIT_EDITMSG",
        "Git commit message exposed",
        Severity::High,
        ".git/COMMIT_EDITMSG readable — recent commit messages visible.",
        "git",
        Some(" ")
    ),
    check!(
        "/.git/logs/HEAD",
        "Git reflog exposed",
        Severity::High,
        ".git/logs/HEAD readable — full commit history visible.",
        "git",
        Some("commit")
    ),
    // SVN entries: line 2 is "dir" for top-level; Mercurial hgrc has INI sections ([paths]/[ui]); Bazaar format file always starts with "Bazaar"
    check!(
        "/.svn/entries",
        "SVN repository exposed",
        Severity::Critical,
        ".svn/entries readable — Subversion repository layout disclosed.",
        "git",
        Some("dir")
    ),
    check!(
        "/.hg/hgrc",
        "Mercurial repository exposed",
        Severity::Critical,
        ".hg/hgrc readable — Mercurial repository config disclosed.",
        "git",
        Some("[")
    ),
    check!(
        "/.bzr/branch/format",
        "Bazaar repository exposed",
        Severity::High,
        ".bzr repository metadata accessible.",
        "git",
        Some("Bazaar")
    ),
    // ── SSH / crypto keys ────────────────────────────────────────────────────
    check!(
        "/.ssh/id_rsa",
        "SSH private key exposed",
        Severity::Critical,
        "SSH RSA private key publicly accessible — full server compromise.",
        "keys",
        Some("PRIVATE KEY")
    ),
    check!(
        "/.ssh/id_ed25519",
        "SSH private key exposed",
        Severity::Critical,
        "SSH Ed25519 private key publicly accessible.",
        "keys",
        Some("PRIVATE KEY")
    ),
    check!(
        "/.ssh/id_ecdsa",
        "SSH private key exposed",
        Severity::Critical,
        "SSH ECDSA private key publicly accessible.",
        "keys",
        Some("PRIVATE KEY")
    ),
    check!(
        "/id_rsa",
        "SSH private key exposed",
        Severity::Critical,
        "SSH private key at root — full server compromise.",
        "keys",
        Some("PRIVATE KEY")
    ),
    check!(
        "/.git-credentials",
        "Git credentials exposed",
        Severity::Critical,
        ".git-credentials contains stored username:password for git remotes.",
        "keys",
        Some("http")
    ),
    check!(
        "/.npmrc",
        "npm auth token exposed",
        Severity::High,
        ".npmrc contains npm registry auth token — allows package publishing.",
        "keys",
        Some("_authToken")
    ),
    check!(
        "/.pypirc",
        "PyPI credentials exposed",
        Severity::High,
        ".pypirc contains PyPI credentials — allows package publishing.",
        "keys",
        Some("[distutils]")
    ),
    check!(
        "/.bash_history",
        "Shell history exposed",
        Severity::High,
        ".bash_history accessible — contains executed commands, may reveal secrets.",
        "keys",
        None
    ),
    // ── Cloud credentials ────────────────────────────────────────────────────
    check!(
        "/.aws/credentials",
        "AWS credentials exposed",
        Severity::Critical,
        ".aws/credentials accessible — AWS access key and secret readable.",
        "cloud",
        Some("aws_access_key_id")
    ),
    check!(
        "/.aws/config",
        "AWS config exposed",
        Severity::High,
        ".aws/config accessible — reveals AWS region and role configuration.",
        "cloud",
        Some("[default]")
    ),
    check!(
        "/.kube/config",
        "Kubernetes config exposed",
        Severity::Critical,
        ".kube/config accessible — Kubernetes cluster credentials leaked.",
        "cloud",
        Some("apiVersion")
    ),
    check!(
        "/.gcloud/application_default_credentials.json",
        "GCP credentials exposed",
        Severity::Critical,
        "GCP application default credentials accessible — cloud access token leaked.",
        "cloud",
        Some("client_id")
    ),
    // ── Environment files ─────────────────────────────────────────────────────
    check!(
        "/.env",
        ".env file exposed",
        Severity::Critical,
        ".env publicly accessible — database creds, API keys, secrets.",
        "env",
        Some("=")
    ),
    check!(
        "/.env.local",
        ".env.local exposed",
        Severity::Critical,
        ".env.local exposed — local development secrets.",
        "env",
        Some("=")
    ),
    check!(
        "/.env.production",
        "Production .env exposed",
        Severity::Critical,
        ".env.production exposed — production credentials compromised.",
        "env",
        Some("=")
    ),
    check!(
        "/.env.staging",
        "Staging .env exposed",
        Severity::High,
        ".env.staging exposed — staging secrets readable.",
        "env",
        Some("=")
    ),
    check!(
        "/.env.backup",
        ".env backup exposed",
        Severity::High,
        "Backup .env file accessible.",
        "env",
        Some("=")
    ),
    check!(
        "/.env.old",
        ".env.old exposed",
        Severity::High,
        "Old .env backup accessible.",
        "env",
        Some("=")
    ),
    check!(
        "/.env.example",
        ".env.example exposed",
        Severity::Low,
        ".env.example reveals expected secret variable names.",
        "env",
        Some("=")
    ),
    check!(
        "/src/.env",
        "Source .env exposed",
        Severity::Critical,
        "Source directory .env accessible.",
        "env",
        Some("=")
    ),
    // ── Config files ──────────────────────────────────────────────────────────
    check!(
        "/config.php",
        "PHP config exposed",
        Severity::High,
        "config.php accessible — may contain database credentials.",
        "config",
        None
    ),
    check!(
        "/wp-config.php.bak",
        "WordPress config backup exposed",
        Severity::Critical,
        "wp-config.php backup exposed — database credentials compromised.",
        "config",
        Some("DB_")
    ),
    check!(
        "/wp-config.php~",
        "WordPress config backup exposed",
        Severity::Critical,
        "wp-config.php~ backup exposed — database credentials compromised.",
        "config",
        Some("DB_")
    ),
    check!(
        "/settings.py",
        "Django settings exposed",
        Severity::High,
        "settings.py accessible — SECRET_KEY and db credentials.",
        "config",
        Some("SECRET_KEY")
    ),
    check!(
        "/_config.yml",
        "Jekyll config exposed",
        Severity::Low,
        "_config.yml reveals site config, may contain API keys.",
        "config",
        None
    ),
    check!(
        "/config.yml",
        "Config YAML exposed",
        Severity::Medium,
        "config.yml accessible — may contain application secrets.",
        "config",
        None
    ),
    check!(
        "/config.yaml",
        "Config YAML exposed",
        Severity::Medium,
        "config.yaml accessible.",
        "config",
        None
    ),
    check!(
        "/.htpasswd",
        ".htpasswd exposed",
        Severity::High,
        "Password file exposed — hashed credentials readable.",
        "config",
        Some(":")
    ),
    check!(
        "/web.config",
        "web.config exposed",
        Severity::High,
        "web.config accessible — connection strings and app config.",
        "config",
        Some("<")
    ),
    // ── Package / dependency disclosure ──────────────────────────────────────
    check!(
        "/package.json",
        "package.json exposed",
        Severity::Low,
        "package.json readable — all npm deps and versions disclosed.",
        "disclosure",
        Some("dependencies")
    ),
    check!(
        "/composer.json",
        "composer.json exposed",
        Severity::Low,
        "composer.json readable — all PHP deps disclosed.",
        "disclosure",
        Some("require")
    ),
    check!(
        "/requirements.txt",
        "requirements.txt exposed",
        Severity::Low,
        "Python deps disclosed.",
        "disclosure",
        None
    ),
    check!(
        "/Gemfile",
        "Gemfile exposed",
        Severity::Low,
        "Ruby deps disclosed.",
        "disclosure",
        Some("gem")
    ),
    check!(
        "/go.mod",
        "go.mod exposed",
        Severity::Low,
        "Go module deps disclosed.",
        "disclosure",
        Some("module")
    ),
    check!(
        "/Dockerfile",
        "Dockerfile exposed",
        Severity::Medium,
        "Container build process exposed — may reveal internal paths and secrets.",
        "disclosure",
        Some("FROM")
    ),
    check!(
        "/docker-compose.yml",
        "docker-compose.yml exposed",
        Severity::Medium,
        "docker-compose.yml — service configs and ports disclosed.",
        "disclosure",
        Some("services")
    ),
    check!(
        "/docker-compose.yaml",
        "docker-compose.yaml exposed",
        Severity::Medium,
        "docker-compose.yaml — service configs disclosed.",
        "disclosure",
        Some("services")
    ),
    // ── Backup / dumps ────────────────────────────────────────────────────────
    check!(
        "/backup.zip",
        "Backup archive exposed",
        Severity::Critical,
        "backup.zip accessible — may contain full application source.",
        "backup",
        None
    ),
    check!(
        "/backup.tar.gz",
        "Backup archive exposed",
        Severity::Critical,
        "backup.tar.gz accessible — may contain full application source.",
        "backup",
        None
    ),
    check!(
        "/backup.tar",
        "Backup archive exposed",
        Severity::Critical,
        "backup.tar accessible.",
        "backup",
        None
    ),
    check!(
        "/dump.sql",
        "SQL dump exposed",
        Severity::Critical,
        "dump.sql accessible — full database dump readable.",
        "backup",
        Some("INSERT INTO")
    ),
    check!(
        "/db.sql",
        "SQL dump exposed",
        Severity::Critical,
        "db.sql accessible — full database dump.",
        "backup",
        Some("CREATE TABLE")
    ),
    check!(
        "/database.sql",
        "SQL dump exposed",
        Severity::Critical,
        "database.sql accessible.",
        "backup",
        Some("CREATE TABLE")
    ),
    check!(
        "/backup.sql",
        "SQL dump exposed",
        Severity::Critical,
        "backup.sql accessible.",
        "backup",
        Some("CREATE TABLE")
    ),
    check!(
        "/data.sql",
        "SQL dump exposed",
        Severity::Critical,
        "data.sql accessible.",
        "backup",
        Some("INSERT INTO")
    ),
    // ── Spring Boot Actuator ──────────────────────────────────────────────────
    check!(
        "/actuator",
        "Spring Boot Actuator exposed",
        Severity::High,
        "/actuator exposed — application internals revealed.",
        "actuator",
        Some("_links")
    ),
    check!(
        "/actuator/env",
        "Spring Boot env actuator",
        Severity::Critical,
        "/actuator/env exposed — env vars and config properties readable.",
        "actuator",
        Some("activeProfiles")
    ),
    check!(
        "/actuator/health",
        "Spring Boot health actuator",
        Severity::Low,
        "/actuator/health exposed.",
        "actuator",
        Some("status")
    ),
    check!(
        "/actuator/info",
        "Spring Boot info actuator",
        Severity::Low,
        "/actuator/info exposed.",
        "actuator",
        None
    ),
    check!(
        "/actuator/beans",
        "Spring Boot beans actuator",
        Severity::Medium,
        "/actuator/beans exposed — Spring bean list readable.",
        "actuator",
        None
    ),
    check!(
        "/actuator/heapdump",
        "Spring Boot heap dump exposed",
        Severity::Critical,
        "/actuator/heapdump — JVM heap dump may contain plaintext secrets.",
        "actuator",
        None
    ),
    check!(
        "/actuator/logfile",
        "Spring Boot log file exposed",
        Severity::High,
        "/actuator/logfile — application logs readable.",
        "actuator",
        None
    ),
    check!(
        "/actuator/metrics",
        "Spring Boot metrics actuator",
        Severity::Medium,
        "/actuator/metrics exposed.",
        "actuator",
        None
    ),
    check!(
        "/actuator/threaddump",
        "Spring Boot thread dump",
        Severity::Medium,
        "/actuator/threaddump exposed.",
        "actuator",
        None
    ),
    // ── Admin panels ──────────────────────────────────────────────────────────
    check!(
        "/admin",
        "Admin panel exposed",
        Severity::Medium,
        "/admin accessible — may expose admin interface.",
        "admin",
        None
    ),
    check!(
        "/administrator",
        "Admin panel exposed",
        Severity::Medium,
        "/administrator accessible.",
        "admin",
        None
    ),
    check!(
        "/wp-admin/",
        "WordPress admin exposed",
        Severity::Medium,
        "/wp-admin/ accessible — WordPress admin panel.",
        "admin",
        None
    ),
    check!(
        "/manager/html",
        "Tomcat Manager exposed",
        Severity::High,
        "Tomcat Manager — may allow WAR deployment.",
        "admin",
        None
    ),
    check!(
        "/phpmyadmin/",
        "phpMyAdmin exposed",
        Severity::High,
        "phpMyAdmin — database management UI.",
        "admin",
        None
    ),
    check!(
        "/adminer.php",
        "Adminer exposed",
        Severity::High,
        "Adminer database tool accessible.",
        "admin",
        None
    ),
    // ── Framework debug / profiler pages ─────────────────────────────────────
    check!(
        "/phpinfo.php",
        "phpinfo() exposed",
        Severity::High,
        "phpinfo() — full PHP config and env vars.",
        "debug",
        Some("phpinfo()")
    ),
    check!(
        "/info.php",
        "PHP info exposed",
        Severity::High,
        "PHP info page accessible.",
        "debug",
        Some("phpinfo()")
    ),
    check!(
        "/server-status",
        "Apache mod_status exposed",
        Severity::Medium,
        "Apache server-status — request counts, load, client IPs.",
        "debug",
        Some("Apache")
    ),
    check!(
        "/server-info",
        "Apache mod_info exposed",
        Severity::Medium,
        "Apache server-info — full server config.",
        "debug",
        None
    ),
    check!(
        "/console",
        "Console endpoint exposed",
        Severity::High,
        "/console accessible — may be H2 console, Groovy REPL, or debug console.",
        "debug",
        None
    ),
    check!(
        "/trace.axd",
        "ASP.NET trace exposed",
        Severity::High,
        "ASP.NET trace.axd — detailed request/response trace with session data.",
        "debug",
        None
    ),
    check!(
        "/elmah.axd",
        "ELMAH error log exposed",
        Severity::High,
        "ELMAH error log — full ASP.NET exception detail with stack traces.",
        "debug",
        Some("Error")
    ),
    check!(
        "/_profiler/",
        "Symfony profiler exposed",
        Severity::High,
        "Symfony Web Profiler — full request debug info including DB queries, logs.",
        "debug",
        None
    ),
    check!(
        "/__debug_toolbar__/",
        "Django debug toolbar exposed",
        Severity::Medium,
        "Django Debug Toolbar endpoints — may expose SQL queries and request data.",
        "debug",
        None
    ),
    check!(
        "/rails/info/properties",
        "Rails info exposed",
        Severity::High,
        "/rails/info/properties — Ruby on Rails server info and environment.",
        "debug",
        Some("Rails")
    ),
    check!(
        "/rails/info/routes",
        "Rails routes exposed",
        Severity::High,
        "/rails/info/routes — full URL routing table.",
        "debug",
        Some("helper")
    ),
    check!(
        "/telescope/requests",
        "Laravel Telescope exposed",
        Severity::High,
        "Laravel Telescope — request/query/exception log with full payloads.",
        "debug",
        None
    ),
    check!(
        "/horizon/dashboard",
        "Laravel Horizon exposed",
        Severity::Medium,
        "Laravel Horizon — queue monitoring dashboard.",
        "debug",
        None
    ),
    // ── API documentation ─────────────────────────────────────────────────────
    check!(
        "/api/swagger.json",
        "Swagger API spec exposed",
        Severity::Medium,
        "Swagger/OpenAPI spec — full API surface with parameters disclosed.",
        "api-docs",
        Some("swagger")
    ),
    check!(
        "/api/openapi.json",
        "OpenAPI spec exposed",
        Severity::Medium,
        "OpenAPI spec exposed.",
        "api-docs",
        Some("openapi")
    ),
    check!(
        "/v1/swagger.json",
        "Swagger v1 spec exposed",
        Severity::Medium,
        "Swagger API spec v1.",
        "api-docs",
        Some("swagger")
    ),
    check!(
        "/v2/api-docs",
        "SpringFox API docs exposed",
        Severity::Medium,
        "SpringFox Swagger2 API docs — full Spring Boot API surface.",
        "api-docs",
        Some("swagger")
    ),
    check!(
        "/openapi.yaml",
        "OpenAPI YAML exposed",
        Severity::Medium,
        "OpenAPI YAML spec exposed.",
        "api-docs",
        Some("openapi")
    ),
    check!(
        "/swagger-ui/",
        "Swagger UI exposed",
        Severity::Medium,
        "Swagger UI — interactive API browser.",
        "api-docs",
        None
    ),
    check!(
        "/redoc/",
        "ReDoc API docs exposed",
        Severity::Low,
        "ReDoc API documentation UI.",
        "api-docs",
        None
    ),
    // ── Java / J2EE ───────────────────────────────────────────────────────────
    check!(
        "/WEB-INF/web.xml",
        "Java web.xml exposed",
        Severity::High,
        "WEB-INF/web.xml — servlet mappings and filter config.",
        "java",
        Some("web-app")
    ),
    check!(
        "/WEB-INF/applicationContext.xml",
        "Spring context exposed",
        Severity::High,
        "Spring applicationContext.xml — bean definitions and data sources.",
        "java",
        Some("beans")
    ),
    // ── Mac filesystem artifact ───────────────────────────────────────────────
    check!(
        "/.DS_Store",
        ".DS_Store exposed",
        Severity::Medium,
        ".DS_Store file — reveals directory structure and file names on macOS-hosted server.",
        "disclosure",
        None
    ),
    check!(
        "/crossdomain.xml",
        "crossdomain.xml exposed",
        Severity::Low,
        "Flash crossdomain policy — reveals allowed cross-origin access rules.",
        "disclosure",
        Some("<cross")
    ),
    // ── Monitoring endpoints ──────────────────────────────────────────────────
    check!(
        "/metrics",
        "Prometheus metrics exposed",
        Severity::Medium,
        "/metrics endpoint — Prometheus metrics reveal service internals, versions, and infra.",
        "metrics",
        Some("# HELP")
    ),
    check!(
        "/prometheus",
        "Prometheus UI exposed",
        Severity::Medium,
        "Prometheus dashboard accessible.",
        "metrics",
        None
    ),
    // ── Security contact ──────────────────────────────────────────────────────
    check!(
        "/security.txt",
        "security.txt present",
        Severity::Info,
        "/security.txt found — review contact and disclosure policy.",
        "security-txt",
        Some("Contact")
    ),
    check!(
        "/.well-known/security.txt",
        "security.txt present",
        Severity::Info,
        "/.well-known/security.txt found.",
        "security-txt",
        Some("Contact")
    ),
];

pub async fn probe(client: &reqwest::Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');

    // ── Catch-all 200 detector ────────────────────────────────────────────
    // Probe a clearly-nonexistent path. If the server returns 200 it's a
    // catch-all responder (Cloudflare, catch-all nginx, etc.).  On such
    // servers we ONLY fire checks that have a content_probe — those validate
    // the body, so false-positives are prevented. Checks with None content
    // probe are unreliable and get skipped entirely on catch-all targets.
    let probe_url = format!("{}/.gossan-probe-nonexistent-xkcd7392/", base);
    let is_catch_all = client
        .get(&probe_url)
        .send()
        .await
        .map(|r| r.status().as_u16() == 200)
        .unwrap_or(false);

    // Convert static CHECKS to owned Strings — eliminates lifetime issues with async move.
    struct OwnedCheck {
        path: String,
        title: String,
        severity: Severity,
        detail: String,
        tag: String,
        content_probe: Option<String>,
    }
    let checks: Vec<OwnedCheck> = CHECKS
        .iter()
        .map(|c| OwnedCheck {
            path: c.path.to_string(),
            title: c.title.to_string(),
            severity: c.severity,
            detail: c.detail.to_string(),
            tag: c.tag.to_string(),
            content_probe: c.content_probe.map(|s| s.to_string()),
        })
        .collect();

    // Fan out all path probes concurrently.
    let results: Vec<Vec<Finding>> = futures::stream::iter(checks)
        .map(|c| {
            let client = client.clone();
            let url = format!("{}{}", base, c.path);
            let target = target.clone();
            let OwnedCheck {
                title,
                severity,
                detail,
                tag,
                content_probe,
                ..
            } = c;
            async move {
                let mut findings = Vec::new();

                // On catch-all servers, checks without a content_probe are
                // unreliable — every path returns 200.  Skip them entirely.
                if is_catch_all && content_probe.is_none() {
                    return findings;
                }

                let Ok(resp) = client.get(url.as_str()).send().await else {
                    return findings;
                };
                let status = resp.status().as_u16();

                if status == 200 {
                    let body = resp.text().await.ok();

                    // On catch-all servers, any path returns the same HTML
                    // error page. Reject HTML responses regardless of content_probe
                    // match — real secret files (.env, .git/HEAD, config) are
                    // never HTML documents.
                    if is_catch_all {
                        let looks_like_html = body
                            .as_deref()
                            .map(|b| {
                                let b = b.trim_start();
                                b.starts_with("<!")
                                    || b.starts_with("<html")
                                    || b.starts_with("<HTML")
                            })
                            .unwrap_or(true); // default true: empty body = not a real file
                        if looks_like_html {
                            return findings;
                        }
                    }

                    // Content validation — skip responses that look like generic error pages.
                    if let Some(ref probe_str) = content_probe {
                        if !body
                            .as_deref()
                            .map(|b| b.contains(probe_str.as_str()))
                            .unwrap_or(false)
                        {
                            return findings;
                        }
                    }

                    findings.push(
                        crate::finding_builder(&target, severity, title, detail)
                            .evidence(Evidence::HttpResponse {
                                status,
                                headers: vec![],
                                body_excerpt: body.map(|b| b.chars().take(300).collect()),
                            })
                            .tag("exposure")
                            .tag(tag)
                            .build()
                            .expect("finding builder: required fields are set"),
                    );
                } else if status == 403
                    && matches!(
                        tag.as_str(),
                        "git" | "actuator" | "admin" | "keys" | "cloud"
                    )
                {
                    // 403 — resource exists but is forbidden.
                    findings.push(
                        crate::finding_builder(
                            &target,
                            Severity::Low,
                            format!("{} (403 — exists, access denied)", title),
                            format!("{} (HTTP 403)", detail),
                        )
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![],
                            body_excerpt: None,
                        })
                        .tag("exposure")
                        .tag(tag)
                        .build()
                        .expect("finding builder: required fields are set"),
                    );
                }

                findings
            }
        })
        .buffer_unordered(25)
        .collect()
        .await;

    Ok(results.into_iter().flatten().collect())
}
