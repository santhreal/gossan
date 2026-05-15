//! TOML-defined service classification rules.
//!
//! Each rule matches a banner pattern and extracts service metadata.
//! Rules are loaded from `rules/` directory, user-extensible.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// A single service classification rule.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceRule {
    /// Unique rule identifier (e.g., "http-apache").
    pub id: String,
    /// Human-readable service name (e.g., "Apache HTTP Server").
    pub service: String,
    /// Protocol this rule applies to (tcp/udp).
    pub protocol: String,
    /// Ports this rule commonly matches (hint, not filter).
    pub common_ports: Vec<u16>,
    /// Banner patterns to match (any match triggers the rule).
    pub patterns: Vec<String>,
    /// Regex for version extraction (capture group 1 = version).
    pub version_pattern: Option<String>,
    /// Security signals this service may emit.
    pub security_signals: Vec<String>,
    /// Priority (higher = preferred when multiple rules match).
    pub priority: u8,
}

#[derive(Debug, Deserialize)]
struct ServiceRulesFile {
    #[serde(default)]
    rule: Vec<ServiceRule>,
}

/// Load custom service-classification rules from a TOML file.
///
/// Schema: a `[[rule]]` array with each entry shaped like
/// [`ServiceRule`]. Returns the parsed rules or an `io::Error` /
/// `toml::de::Error` wrapped in `anyhow::Error`.
///
/// ```toml
/// [[rule]]
/// id = "custom-service"
/// service = "MyService"
/// protocol = "tcp"
/// common_ports = [9999]
/// patterns = ["MYSERVICE/"]
/// version_pattern = "MYSERVICE/(\\d+\\.\\d+)"
/// security_signals = []
/// priority = 5
/// ```
pub fn load_from_toml<P: AsRef<Path>>(path: P) -> Result<Vec<ServiceRule>, anyhow::Error> {
    let body = std::fs::read_to_string(path.as_ref())?;
    let parsed: ServiceRulesFile = toml::from_str(&body)?;
    Ok(parsed.rule)
}

/// Load custom rules + the built-in set, in that order. Custom
/// rules take precedence (appear first) so a higher-priority custom
/// rule can override a built-in.
pub fn builtin_plus<P: AsRef<Path>>(custom_path: P) -> Vec<ServiceRule> {
    let mut out = load_from_toml(custom_path).unwrap_or_default();
    out.extend(builtin_rules());
    out
}

/// Result of classifying a banner.
#[derive(Debug, Clone)]
pub struct ServiceMatch {
    /// The rule that matched.
    pub rule_id: String,
    /// Identified service name.
    pub service: String,
    /// Extracted version, if available.
    pub version: Option<String>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f32,
    /// Security signals detected in the banner.
    pub signals: Vec<String>,
    /// Additional metadata extracted.
    pub metadata: HashMap<String, String>,
}

/// Built-in rule definitions.
///
/// These cover the most common services. Users extend via TOML files
/// in a `rules/` directory.
pub fn builtin_rules() -> Vec<ServiceRule> {
    let mut out = vec![
        // ── HTTP servers ──────────────────────────────────────────────
        ServiceRule {
            id: "http-apache".into(),
            service: "Apache HTTP Server".into(),
            protocol: "tcp".into(),
            common_ports: vec![80, 443, 8080, 8443],
            patterns: vec![
                "Apache/".into(),
                "Server: Apache".into(),
            ],
            version_pattern: Some(r"Apache/(\d+\.\d+\.\d+)".into()),
            security_signals: vec![
                "server-version-disclosure".into(),
            ],
            priority: 10,
        },
        ServiceRule {
            id: "http-nginx".into(),
            service: "nginx".into(),
            protocol: "tcp".into(),
            common_ports: vec![80, 443, 8080, 8443],
            patterns: vec![
                "nginx/".into(),
                "Server: nginx".into(),
            ],
            version_pattern: Some(r"nginx/(\d+\.\d+\.\d+)".into()),
            security_signals: vec![
                "server-version-disclosure".into(),
            ],
            priority: 10,
        },
        ServiceRule {
            id: "http-iis".into(),
            service: "Microsoft IIS".into(),
            protocol: "tcp".into(),
            common_ports: vec![80, 443, 8080],
            patterns: vec![
                "Microsoft-IIS/".into(),
                "Server: Microsoft-IIS".into(),
            ],
            version_pattern: Some(r"Microsoft-IIS/(\d+\.\d+)".into()),
            security_signals: vec![
                "server-version-disclosure".into(),
            ],
            priority: 10,
        },
        // ── SSH ───────────────────────────────────────────────────────
        ServiceRule {
            id: "ssh-openssh".into(),
            service: "OpenSSH".into(),
            protocol: "tcp".into(),
            common_ports: vec![22, 2222],
            patterns: vec![
                "SSH-2.0-OpenSSH".into(),
                "SSH-1.99-OpenSSH".into(),
            ],
            version_pattern: Some(r"OpenSSH[_\s](\d+\.\d+\S*)".into()),
            security_signals: vec![
                "ssh-version-disclosure".into(),
            ],
            priority: 10,
        },
        ServiceRule {
            id: "ssh-dropbear".into(),
            service: "Dropbear SSH".into(),
            protocol: "tcp".into(),
            common_ports: vec![22, 2222],
            patterns: vec!["dropbear".into()],
            version_pattern: Some(r"dropbear[_\s](\d+\.\d+)".into()),
            security_signals: vec!["ssh-version-disclosure".into()],
            priority: 8,
        },
        // ── FTP ───────────────────────────────────────────────────────
        ServiceRule {
            id: "ftp-vsftpd".into(),
            service: "vsftpd".into(),
            protocol: "tcp".into(),
            common_ports: vec![21],
            patterns: vec!["vsftpd".into(), "vsFTPd".into()],
            version_pattern: Some(r"vsftpd\s+(\d+\.\d+\.\d+)".into()),
            security_signals: vec!["ftp-version-disclosure".into()],
            priority: 10,
        },
        ServiceRule {
            id: "ftp-proftpd".into(),
            service: "ProFTPD".into(),
            protocol: "tcp".into(),
            common_ports: vec![21],
            patterns: vec!["ProFTPD".into()],
            version_pattern: Some(r"ProFTPD\s+(\d+\.\d+\.\d+\S*)".into()),
            security_signals: vec!["ftp-version-disclosure".into()],
            priority: 10,
        },
        // ── Databases ─────────────────────────────────────────────────
        ServiceRule {
            id: "mysql".into(),
            service: "MySQL".into(),
            protocol: "tcp".into(),
            common_ports: vec![3306],
            patterns: vec![
                "mysql_native_password".into(),
                "MariaDB".into(),
                "\x00\x00\x00\x0a".into(), // MySQL greeting
            ],
            version_pattern: Some(r"(\d+\.\d+\.\d+)".into()),
            security_signals: vec![
                "database-exposed".into(),
                "version-disclosure".into(),
            ],
            priority: 10,
        },
        ServiceRule {
            id: "postgresql".into(),
            service: "PostgreSQL".into(),
            protocol: "tcp".into(),
            common_ports: vec![5432],
            patterns: vec!["PostgreSQL".into()],
            version_pattern: Some(r"PostgreSQL\s+(\d+\.\d+)".into()),
            security_signals: vec!["database-exposed".into()],
            priority: 10,
        },
        ServiceRule {
            id: "redis".into(),
            service: "Redis".into(),
            protocol: "tcp".into(),
            common_ports: vec![6379],
            patterns: vec![
                "-ERR".into(),
                "+PONG".into(),
                "$".into(),
                "redis_version:".into(),
            ],
            version_pattern: Some(r"redis_version:(\d+\.\d+\.\d+)".into()),
            security_signals: vec![
                "redis-unauthenticated".into(),
                "database-exposed".into(),
            ],
            priority: 10,
        },
        ServiceRule {
            id: "mongodb".into(),
            service: "MongoDB".into(),
            protocol: "tcp".into(),
            common_ports: vec![27017],
            patterns: vec!["ismaster".into(), "MongoDB".into()],
            version_pattern: Some(r"(\d+\.\d+\.\d+)".into()),
            security_signals: vec!["database-exposed".into()],
            priority: 10,
        },
        // ── Mail ──────────────────────────────────────────────────────
        ServiceRule {
            id: "smtp".into(),
            service: "SMTP".into(),
            protocol: "tcp".into(),
            common_ports: vec![25, 465, 587],
            patterns: vec![
                "220 ".into(),
                "ESMTP".into(),
                "Postfix".into(),
                "Exim".into(),
            ],
            version_pattern: Some(r"(?:Postfix|Exim|Sendmail)\s*(\d+\.\d+\S*)".into()),
            security_signals: vec!["smtp-open-relay-check".into()],
            priority: 8,
        },
        // ── Elastic / Kibana ──────────────────────────────────────────
        ServiceRule {
            id: "elasticsearch".into(),
            service: "Elasticsearch".into(),
            protocol: "tcp".into(),
            common_ports: vec![9200, 9300],
            patterns: vec![
                "\"cluster_name\"".into(),
                "\"tagline\" : \"You Know, for Search\"".into(),
            ],
            version_pattern: Some(r#""number"\s*:\s*"(\d+\.\d+\.\d+)""#.into()),
            security_signals: vec![
                "elasticsearch-unauthenticated".into(),
                "search-engine-exposed".into(),
            ],
            priority: 10,
        },
        // ── RDP ───────────────────────────────────────────────────────
        ServiceRule {
            id: "rdp".into(),
            service: "RDP".into(),
            protocol: "tcp".into(),
            common_ports: vec![3389],
            patterns: vec![
                "\x03\x00".into(), // RDP negotiation response
            ],
            version_pattern: None,
            security_signals: vec!["rdp-exposed".into()],
            priority: 10,
        },
    ];
    // Append the curated top-100 expansion below to keep diffs reviewable.
    out.extend(extended_rules());
    out
}

fn extended_rules() -> Vec<ServiceRule> {
    let r = |id: &str, service: &str, protocol: &str, ports: Vec<u16>,
             patterns: Vec<&str>, version: Option<&str>,
             signals: Vec<&str>, priority: u8| -> ServiceRule {
        ServiceRule {
            id: id.into(),
            service: service.into(),
            protocol: protocol.into(),
            common_ports: ports,
            patterns: patterns.into_iter().map(String::from).collect(),
            version_pattern: version.map(String::from),
            security_signals: signals.into_iter().map(String::from).collect(),
            priority,
        }
    };
    vec![
        // ── HTTP servers (additional) ─────────────────────────────────
        r("http-haproxy", "HAProxy", "tcp", vec![80, 443, 8080, 8443],
            vec!["Server: HAProxy", "HAProxy", "X-Haproxy"],
            Some(r"HAProxy[/\s]+(\d+\.\d+(?:\.\d+)?)"),
            vec!["server-version-disclosure"], 9),
        r("http-caddy", "Caddy", "tcp", vec![80, 443, 2015, 2019],
            vec!["Server: Caddy"],
            Some(r"Caddy/(\d+\.\d+\.\d+)"),
            vec!["server-version-disclosure"], 10),
        r("http-litespeed", "LiteSpeed", "tcp", vec![80, 443, 7080],
            vec!["Server: LiteSpeed", "LiteSpeed/"],
            Some(r"LiteSpeed[/\s](\d+\.\d+\.\d+)"),
            vec!["server-version-disclosure"], 9),
        r("http-tomcat", "Apache Tomcat", "tcp", vec![8080, 8443, 8005, 8009],
            vec!["Apache-Coyote/", "Apache Tomcat"],
            Some(r"Apache Tomcat/?(\d+\.\d+\.\d+)"),
            vec!["servlet-container-exposed", "server-version-disclosure"], 10),
        r("http-jetty", "Eclipse Jetty", "tcp", vec![8080, 8443],
            vec!["Server: Jetty", "Jetty("],
            Some(r"Jetty\(?(\d+\.\d+\.\d+)"),
            vec!["server-version-disclosure"], 9),
        r("http-tornado", "Tornado", "tcp", vec![8888, 8080],
            vec!["Server: TornadoServer"],
            Some(r"TornadoServer/(\d+\.\d+\.\d+)"),
            vec!["server-version-disclosure"], 8),
        r("http-gunicorn", "Gunicorn", "tcp", vec![8000, 8080],
            vec!["Server: gunicorn"],
            Some(r"gunicorn/(\d+\.\d+\.\d+)"),
            vec!["server-version-disclosure"], 8),
        r("http-werkzeug", "Werkzeug", "tcp", vec![5000, 8000],
            vec!["Werkzeug/"],
            Some(r"Werkzeug/(\d+\.\d+\.\d+)"),
            vec!["debug-server-exposed", "server-version-disclosure"], 9),
        r("http-uvicorn", "Uvicorn", "tcp", vec![8000, 8080],
            vec!["Server: uvicorn"],
            Some(r"uvicorn"),
            vec!["server-version-disclosure"], 7),
        r("http-puma", "Puma", "tcp", vec![3000, 9292],
            vec!["Server: puma"],
            Some(r"puma\s+(\d+\.\d+\.\d+)"),
            vec!["server-version-disclosure"], 8),
        r("http-unicorn", "Unicorn", "tcp", vec![3000, 8080],
            vec!["Server: Unicorn"],
            Some(r"Unicorn\s+(\d+\.\d+\.\d+)"),
            vec!["server-version-disclosure"], 7),
        r("http-node-express", "Express (Node)", "tcp", vec![3000, 8080],
            vec!["X-Powered-By: Express"],
            None, vec!["framework-disclosure"], 8),
        r("http-aws-elb", "AWS ELB", "tcp", vec![80, 443],
            vec!["Server: awselb"],
            Some(r"awselb/(\d+\.\d+)"), vec![], 7),
        r("http-cloudflare", "Cloudflare", "tcp", vec![80, 443],
            vec!["Server: cloudflare", "CF-Ray:"],
            None, vec!["cdn-fronted"], 6),
        r("http-akamai", "Akamai", "tcp", vec![80, 443],
            vec!["Server: AkamaiGHost", "AkamaiGHost"],
            None, vec!["cdn-fronted"], 6),
        r("http-fastly", "Fastly", "tcp", vec![80, 443],
            vec!["X-Served-By: cache-", "Via: 1.1 varnish", "Fastly-Debug"],
            None, vec!["cdn-fronted"], 5),
        r("http-varnish", "Varnish", "tcp", vec![80, 443, 6081, 6082],
            vec!["Via: 1.1 varnish", "X-Varnish:"],
            Some(r"varnish\s+v?(\d+\.\d+\.\d+)"), vec![], 7),
        r("http-traefik", "Traefik", "tcp", vec![80, 443, 8080],
            vec!["Server: Traefik"],
            Some(r"Traefik/(\d+\.\d+\.\d+)"), vec!["server-version-disclosure"], 8),
        r("http-envoy", "Envoy", "tcp", vec![80, 443, 9901],
            vec!["Server: envoy", "X-Envoy-Upstream-Service-Time"],
            None, vec![], 7),

        // ── Caches / KV ───────────────────────────────────────────────
        r("memcached", "Memcached", "tcp", vec![11211],
            vec!["VERSION ", "STAT pid"],
            Some(r"VERSION\s+(\d+\.\d+\.\d+)"),
            vec!["memcached-unauthenticated", "database-exposed"], 10),
        r("etcd", "etcd", "tcp", vec![2379, 2380],
            vec!["etcdserver", "/v2/keys", "/version"],
            Some(r#""etcdserver"\s*:\s*"(\d+\.\d+\.\d+)""#),
            vec!["etcd-exposed"], 10),
        r("consul", "Consul", "tcp", vec![8500, 8501, 8600],
            vec!["X-Consul-Index", "Consul Agent"],
            Some(r"Consul/(\d+\.\d+\.\d+)"), vec!["consul-exposed"], 10),
        r("vault", "HashiCorp Vault", "tcp", vec![8200, 8201],
            vec!["X-Vault-", "vault/"],
            Some(r"vault/(\d+\.\d+\.\d+)"), vec!["vault-api-exposed"], 10),

        // ── Document / column DBs ─────────────────────────────────────
        r("couchdb", "CouchDB", "tcp", vec![5984, 6984],
            vec!["Welcome to Apache CouchDB", "couchdb"],
            Some(r#""version"\s*:\s*"(\d+\.\d+\.\d+)""#),
            vec!["database-exposed"], 10),
        r("cassandra", "Cassandra", "tcp", vec![9042, 7000, 7199],
            vec!["Apache Cassandra"],
            Some(r"Cassandra\s+(\d+\.\d+\.\d+)"),
            vec!["database-exposed"], 9),
        r("clickhouse", "ClickHouse", "tcp", vec![8123, 9000, 9009],
            vec!["X-ClickHouse-Server-Display-Name"],
            Some(r"ClickHouse/(\d+\.\d+\.\d+)"),
            vec!["database-exposed"], 9),
        r("influxdb", "InfluxDB", "tcp", vec![8086, 8088],
            vec!["X-Influxdb-Version"],
            Some(r"X-Influxdb-Version:\s*(\d+\.\d+\.\d+)"),
            vec!["database-exposed"], 9),

        // ── Message brokers / streams ─────────────────────────────────
        r("rabbitmq", "RabbitMQ", "tcp", vec![5672, 15672, 25672],
            vec!["RabbitMQ", "AMQP\x00\x00"],
            Some(r"RabbitMQ[/\s](\d+\.\d+\.\d+)"),
            vec!["message-broker-exposed"], 10),
        r("rabbitmq-mgmt", "RabbitMQ Management", "tcp", vec![15672],
            vec!["RabbitMQ Management"],
            Some(r"RabbitMQ\s+(\d+\.\d+\.\d+)"),
            vec!["mgmt-ui-exposed"], 9),
        r("kafka", "Kafka", "tcp", vec![9092, 9093, 9094],
            vec!["org.apache.kafka", "broker.id"],
            None, vec!["broker-exposed"], 9),
        r("zookeeper", "ZooKeeper", "tcp", vec![2181, 2888, 3888],
            vec!["zookeeper.version", "ZooKeeper"],
            Some(r"version=(\d+\.\d+\.\d+)"),
            vec!["zookeeper-exposed"], 10),
        r("nats", "NATS", "tcp", vec![4222, 6222, 8222],
            vec!["INFO {", "\"server_name\""],
            Some(r#""version"\s*:\s*"(\d+\.\d+\.\d+)""#),
            vec!["nats-exposed"], 9),
        r("mosquitto", "Mosquitto MQTT", "tcp", vec![1883, 8883, 9001],
            vec!["mosquitto"],
            Some(r"mosquitto\s+version\s+(\d+\.\d+\.\d+)"),
            vec!["mqtt-exposed"], 9),
        r("pulsar", "Apache Pulsar", "tcp", vec![6650, 8080, 6651],
            vec!["pulsar://", "Pulsar"],
            Some(r"Pulsar\s+(\d+\.\d+\.\d+)"),
            vec!["broker-exposed"], 8),

        // ── Container & orchestration ────────────────────────────────
        r("docker-daemon", "Docker daemon", "tcp", vec![2375, 2376],
            vec!["Docker/", "ApiVersion", "\"DockerRootDir\""],
            Some(r"Docker/(\d+\.\d+\.\d+)"),
            vec!["docker-api-exposed", "rce-on-unauth"], 10),
        r("kubernetes-api", "Kubernetes API", "tcp", vec![6443, 8443, 10250],
            vec!["k8s.io", "/api/v1", "\"kind\":\"APIVersions\""],
            Some(r#""gitVersion"\s*:\s*"v(\d+\.\d+\.\d+)""#),
            vec!["k8s-api-exposed"], 10),
        r("portainer", "Portainer", "tcp", vec![9000, 9443],
            vec!["Portainer", "X-Portainer"],
            Some(r"Portainer-(\d+\.\d+\.\d+)"), vec!["mgmt-ui-exposed"], 9),
        r("rancher", "Rancher", "tcp", vec![8443, 80, 443],
            vec!["X-Rancher-", "rancher"],
            Some(r"rancher/(\d+\.\d+\.\d+)"), vec!["mgmt-ui-exposed"], 8),
        r("kubelet", "kubelet", "tcp", vec![10250, 10255, 10256],
            vec!["/runningpods", "/healthz", "kubelet"],
            None, vec!["kubelet-exposed", "rce-on-unauth"], 10),

        // ── CI/CD ────────────────────────────────────────────────────
        r("jenkins", "Jenkins", "tcp", vec![8080, 50000, 8443],
            vec!["X-Jenkins:", "Jenkins-Version"],
            Some(r"X-Jenkins:\s*(\d+\.\d+(?:\.\d+)?)"),
            vec!["ci-server-exposed"], 10),
        r("gitlab", "GitLab", "tcp", vec![80, 443, 8081],
            vec!["GitLab", "X-Gitlab-Meta"],
            Some(r"GitLab/(\d+\.\d+\.\d+)"),
            vec!["scm-server-exposed"], 9),
        r("gitea", "Gitea", "tcp", vec![3000, 80, 443],
            vec!["Gitea", "X-Gitea-"],
            Some(r"Gitea/(\d+\.\d+\.\d+)"),
            vec!["scm-server-exposed"], 9),
        r("gerrit", "Gerrit", "tcp", vec![8080, 29418],
            vec!["Gerrit-", "X-Gerrit-"],
            Some(r"Gerrit/(\d+\.\d+\.\d+)"),
            vec!["scm-server-exposed"], 8),
        r("sonarqube", "SonarQube", "tcp", vec![9000, 9001],
            vec!["SonarQube", "x-sonar-"],
            Some(r"SonarQube/(\d+\.\d+\.\d+)"),
            vec!["mgmt-ui-exposed"], 8),
        r("nexus", "Sonatype Nexus", "tcp", vec![8081, 8443],
            vec!["X-Nexus-", "Server: Nexus"],
            Some(r"Nexus/(\d+\.\d+\.\d+)"),
            vec!["registry-exposed"], 9),
        r("artifactory", "JFrog Artifactory", "tcp", vec![8081, 8082],
            vec!["X-JFrog-Art-", "X-Artifactory-"],
            Some(r"Artifactory/(\d+\.\d+\.\d+)"),
            vec!["registry-exposed"], 9),
        r("teamcity", "JetBrains TeamCity", "tcp", vec![8111, 80, 443],
            vec!["TeamCity", "X-TeamCity-"],
            Some(r"TeamCity (\d+\.\d+\.\d+)"),
            vec!["ci-server-exposed"], 8),
        r("concourse", "Concourse CI", "tcp", vec![8080],
            vec!["X-Concourse-", "concourse-version"],
            Some(r"v(\d+\.\d+\.\d+)"), vec!["ci-server-exposed"], 7),
        r("drone-ci", "Drone CI", "tcp", vec![80, 443, 8000],
            vec!["X-Drone", "drone/"], None,
            vec!["ci-server-exposed"], 7),
        r("argocd", "ArgoCD", "tcp", vec![80, 443, 8080],
            vec!["X-ArgoCD-", "Argo CD"], None,
            vec!["mgmt-ui-exposed"], 8),
        r("spinnaker", "Spinnaker", "tcp", vec![8084, 9000],
            vec!["X-Spinnaker-"], None,
            vec!["mgmt-ui-exposed"], 7),
        r("harbor", "Harbor", "tcp", vec![80, 443, 4443],
            vec!["X-Harbor-Version", "Harbor-Api-Version"],
            Some(r"X-Harbor-Version:\s*v?(\d+\.\d+\.\d+)"),
            vec!["registry-exposed"], 9),
        r("quay", "Quay", "tcp", vec![80, 443, 8443],
            vec!["X-Quay-", "quay-version"], None,
            vec!["registry-exposed"], 8),

        // ── Atlassian ────────────────────────────────────────────────
        r("bamboo", "Atlassian Bamboo", "tcp", vec![8085, 80, 443],
            vec!["X-AUSERNAME", "Bamboo"], None,
            vec!["ci-server-exposed"], 7),
        r("bitbucket", "Atlassian Bitbucket", "tcp", vec![7990, 7999],
            vec!["X-AUSERNAME", "atl_bitbucket_session"], None,
            vec!["scm-server-exposed"], 7),
        r("confluence", "Confluence", "tcp", vec![8090, 80, 443],
            vec!["X-Confluence-Request-Time"], None,
            vec!["wiki-exposed"], 7),
        r("jira", "Jira", "tcp", vec![8080, 80, 443],
            vec!["X-AREQUESTID", "JSESSIONID", "atlassian.xsrf.token"], None,
            vec!["issue-tracker-exposed"], 7),

        // ── Observability ────────────────────────────────────────────
        r("grafana", "Grafana", "tcp", vec![3000, 80, 443],
            vec!["grafana_session", "X-Grafana-"],
            Some(r"Grafana v(\d+\.\d+\.\d+)"),
            vec!["mgmt-ui-exposed"], 9),
        r("prometheus", "Prometheus", "tcp", vec![9090, 9093, 9100],
            vec!["prometheus_build_info", "/api/v1/query", "Prometheus"],
            Some(r#"version="(\d+\.\d+\.\d+)""#),
            vec!["metrics-exposed"], 9),
        r("alertmanager", "Alertmanager", "tcp", vec![9093, 9094],
            vec!["Alertmanager"], Some(r"Alertmanager/(\d+\.\d+\.\d+)"),
            vec!["mgmt-ui-exposed"], 7),
        r("loki", "Grafana Loki", "tcp", vec![3100],
            vec!["loki", "/loki/api/v1"], Some(r"loki/(\d+\.\d+\.\d+)"),
            vec!["log-server-exposed"], 7),
        r("tempo", "Grafana Tempo", "tcp", vec![3200, 4317, 9411],
            vec!["tempo", "/api/traces"], None,
            vec!["trace-server-exposed"], 6),
        r("kibana", "Kibana", "tcp", vec![5601],
            vec!["kbn-name", "kibana"],
            Some(r#""version"\s*:\s*"(\d+\.\d+\.\d+)""#),
            vec!["mgmt-ui-exposed"], 9),
        r("fluentd", "Fluentd", "tcp", vec![24224, 9880],
            vec!["fluentd"], Some(r"fluentd[/-](\d+\.\d+\.\d+)"),
            vec!["log-server-exposed"], 7),
        r("logstash", "Logstash", "tcp", vec![5044, 9600],
            vec!["logstash"], Some(r"logstash[/-](\d+\.\d+\.\d+)"),
            vec!["log-server-exposed"], 7),

        // ── Auth ────────────────────────────────────────────────────
        r("keycloak", "Keycloak", "tcp", vec![8080, 8443],
            vec!["X-Keycloak-", "kc_restart", "keycloak"],
            Some(r"Keycloak/(\d+\.\d+\.\d+)"),
            vec!["auth-server-exposed"], 8),
        r("openldap", "OpenLDAP", "tcp", vec![389, 636],
            vec!["LDAP", "objectClass"], None,
            vec!["directory-exposed"], 8),
        r("freeradius", "FreeRADIUS", "udp", vec![1812, 1813],
            vec!["FreeRADIUS"], Some(r"FreeRADIUS\s+Version\s+(\d+\.\d+\.\d+)"),
            vec!["radius-exposed"], 7),

        // ── Mail (more) ──────────────────────────────────────────────
        r("dovecot", "Dovecot", "tcp", vec![110, 143, 993, 995],
            vec!["Dovecot ready", "+OK Dovecot"],
            Some(r"Dovecot\s+\(?(\d+\.\d+\.\d+)"),
            vec!["mail-version-disclosure"], 9),
        r("courier-imap", "Courier IMAP", "tcp", vec![143, 993],
            vec!["Courier-IMAP"], Some(r"Courier-IMAP\s+(\d+\.\d+\.\d+)"),
            vec!["mail-version-disclosure"], 7),
        r("sendmail", "Sendmail", "tcp", vec![25, 587],
            vec!["Sendmail"], Some(r"Sendmail\s+(\d+\.\d+\.\d+)"),
            vec!["mail-version-disclosure"], 7),

        // ── File transfer ────────────────────────────────────────────
        r("filezilla-server", "FileZilla Server", "tcp", vec![21, 990],
            vec!["FileZilla Server"],
            Some(r"FileZilla Server\s+(\d+\.\d+\.\d+)"),
            vec!["ftp-version-disclosure"], 8),
        r("pure-ftpd", "Pure-FTPd", "tcp", vec![21],
            vec!["Pure-FTPd"], Some(r"Pure-FTPd\s+(\d+\.\d+\S*)"),
            vec!["ftp-version-disclosure"], 8),
        r("samba", "Samba", "tcp", vec![139, 445],
            vec!["Samba", "SMB"], Some(r"Samba\s+(\d+\.\d+\.\d+)"),
            vec!["smb-exposed"], 9),
        r("nfs", "NFS", "tcp", vec![2049],
            vec!["NFS_PROGRAM"], None,
            vec!["nfs-exposed"], 8),

        // ── Remote management ────────────────────────────────────────
        r("ipmi", "IPMI", "udp", vec![623],
            vec!["IPMI"], None,
            vec!["ipmi-exposed", "remote-mgmt-exposed"], 10),
        r("ilo", "HP iLO", "tcp", vec![80, 443, 17988],
            vec!["Server: HP-iLO", "iLO"],
            Some(r"HP-iLO/(\d+\.\d+)"),
            vec!["remote-mgmt-exposed"], 10),
        r("idrac", "Dell iDRAC", "tcp", vec![80, 443, 5900],
            vec!["iDRAC", "Dell Inc."],
            Some(r"iDRAC[/\s](\d+)"),
            vec!["remote-mgmt-exposed"], 10),
        r("supermicro-ipmi", "Supermicro BMC", "tcp", vec![80, 443],
            vec!["ATEN International", "Supermicro"], None,
            vec!["remote-mgmt-exposed"], 9),

        // ── Printing ─────────────────────────────────────────────────
        r("ipp-cups", "IPP/CUPS", "tcp", vec![631],
            vec!["IPP/", "CUPS"], Some(r"CUPS/(\d+\.\d+\.\d+)"),
            vec!["printer-exposed"], 7),
        r("jetdirect", "HP JetDirect", "tcp", vec![9100],
            vec!["@PJL", "HP JetDirect"], None,
            vec!["printer-exposed"], 7),

        // ── Legacy / clear-text ──────────────────────────────────────
        // Telnet IAC bytes 0xFF/0xFB/0xFD are valid in raw bytes but
        // not in a UTF-8 str literal, so we match the post-IAC "login:"
        // / "Password:" prompt that almost every telnet daemon emits.
        r("telnet", "Telnet", "tcp", vec![23, 2323],
            vec!["login: ", "Password: ", "Welcome to "],
            None, vec!["cleartext-protocol", "telnet-exposed"], 10),
        r("snmp", "SNMP", "udp", vec![161, 162],
            vec!["public", "private"], None,
            vec!["snmp-exposed"], 9),
        r("rpcbind", "rpcbind/portmap", "tcp", vec![111],
            vec!["rpcbind", "program vers"], None,
            vec!["rpc-exposed"], 7),

        // ── DNS servers ──────────────────────────────────────────────
        r("powerdns", "PowerDNS", "udp", vec![53, 8081],
            vec!["PowerDNS"], Some(r"PowerDNS\s+Authoritative\s+Server\s+(\d+\.\d+\.\d+)"),
            vec!["dns-version-disclosure"], 9),
        r("nsd", "NLnet NSD", "udp", vec![53],
            vec!["NSD "], Some(r"NSD\s+(\d+\.\d+\.\d+)"),
            vec!["dns-version-disclosure"], 8),
        r("knot-dns", "Knot DNS", "udp", vec![53],
            vec!["Knot DNS"], Some(r"Knot DNS\s+(\d+\.\d+\.\d+)"),
            vec!["dns-version-disclosure"], 8),
        r("unbound", "Unbound", "udp", vec![53],
            vec!["unbound"], Some(r"unbound\s+(\d+\.\d+\.\d+)"),
            vec!["dns-version-disclosure"], 7),
        r("dnsdist", "dnsdist", "tcp", vec![53, 5199],
            vec!["dnsdist"], Some(r"dnsdist\s+(\d+\.\d+\.\d+)"),
            vec!["dns-version-disclosure"], 7),

        // ── Time / NTP / NTS ─────────────────────────────────────────
        r("ntp", "NTP", "udp", vec![123],
            vec!["\x1c"], None, vec![], 6),

        // ── Misc network services ────────────────────────────────────
        r("openvpn", "OpenVPN", "udp", vec![1194, 443],
            vec!["P_CONTROL", "OpenVPN"], None,
            vec!["vpn-exposed"], 8),
        r("wireguard", "WireGuard", "udp", vec![51820, 443],
            vec!["WireGuard"], None, vec!["vpn-exposed"], 7),
        r("pptp", "PPTP", "tcp", vec![1723],
            vec!["pptp"], None, vec!["legacy-vpn-exposed"], 8),
        r("strongswan", "strongSwan IPsec", "udp", vec![500, 4500],
            vec!["strongSwan"], Some(r"strongSwan\s+(\d+\.\d+\.\d+)"),
            vec!["vpn-exposed"], 7),
        r("xrdp", "xrdp", "tcp", vec![3389],
            vec!["xrdp"], Some(r"xrdp\s+(\d+\.\d+\.\d+)"),
            vec!["rdp-exposed"], 8),
        r("vnc", "VNC", "tcp", vec![5900, 5901, 5902],
            vec!["RFB 003.", "RFB"],
            Some(r"RFB 003\.(\d+)"),
            vec!["vnc-exposed", "remote-desktop-exposed"], 9),

        // ── Game / streaming / chat ──────────────────────────────────
        r("minecraft", "Minecraft Server", "tcp", vec![25565],
            vec!["Minecraft Server", "minecraft.net", "Vanilla 1.", "Bukkit on"],
            None, vec!["game-server-exposed"], 5),
        r("ts3", "TeamSpeak 3", "udp", vec![9987, 10011, 30033],
            vec!["TS3", "TeaSpeak"], None, vec![], 5),
        r("plex", "Plex Media Server", "tcp", vec![32400],
            vec!["X-Plex-", "Plex Media Server"],
            Some(r"X-Plex-Version:\s*(\d+\.\d+\.\d+)"),
            vec!["media-server-exposed"], 6),
        r("jellyfin", "Jellyfin", "tcp", vec![8096, 8920],
            vec!["X-Application", "Jellyfin"],
            Some(r"Jellyfin/(\d+\.\d+\.\d+)"),
            vec!["media-server-exposed"], 6),

        // ── Industrial / IoT (banner-detectable) ─────────────────────
        // Modbus MBAP header is 7 bytes; the ProtocolID at offset 2 is
        // always 0x0000 0x0000 plus a 2-byte length and unit ID. A naked
        // run of zero bytes is too generic — gate on the typical "len=6,
        // unit=1" prefix which catches most server responses without
        // matching arbitrary zero-padded buffers.
        r("modbus", "Modbus TCP", "tcp", vec![502],
            vec!["\u{0}\u{0}\u{0}\u{0}\u{0}\u{6}\u{1}"],
            None, vec!["ics-exposed", "modbus-exposed"], 10),
        r("siemens-s7", "Siemens S7", "tcp", vec![102],
            vec!["S7", "ISO-on-TCP"], None,
            vec!["ics-exposed"], 10),

        // ── Storage protocols ────────────────────────────────────────
        r("iscsi", "iSCSI", "tcp", vec![3260],
            vec!["iSCSI", "iqn."], None,
            vec!["storage-exposed"], 8),
        r("minio", "MinIO", "tcp", vec![9000, 9001],
            vec!["X-Amz-Bucket-Region", "MinIO", "MinIO Console"],
            Some(r"MinIO/(\S+)"), vec!["object-storage-exposed"], 9),

        // ── Search / vector / AI infra ───────────────────────────────
        r("solr", "Apache Solr", "tcp", vec![8983, 7574],
            vec!["Solr", "X-Solr-"],
            Some(r"Solr/(\d+\.\d+\.\d+)"),
            vec!["search-engine-exposed"], 9),
        r("opensearch", "OpenSearch", "tcp", vec![9200],
            vec!["opensearch", "OpenSearch"],
            Some(r#""number"\s*:\s*"(\d+\.\d+\.\d+)""#),
            vec!["search-engine-exposed"], 9),
        r("milvus", "Milvus", "tcp", vec![19530, 9091],
            vec!["milvus"], Some(r"milvus[/\s](\d+\.\d+\.\d+)"),
            vec!["vector-db-exposed"], 7),
        r("qdrant", "Qdrant", "tcp", vec![6333, 6334],
            vec!["qdrant", "Qdrant"], Some(r"Qdrant/(\d+\.\d+\.\d+)"),
            vec!["vector-db-exposed"], 7),
        r("weaviate", "Weaviate", "tcp", vec![8080, 50051],
            vec!["weaviate"], Some(r"weaviate[/\s](\d+\.\d+\.\d+)"),
            vec!["vector-db-exposed"], 7),

        // ── Misc legacy headline ports ───────────────────────────────
        r("smb1", "SMBv1", "tcp", vec![139, 445],
            vec!["SMB 1.0"], None,
            vec!["smbv1-exposed", "deprecated-protocol"], 10),
        r("rsync", "rsync", "tcp", vec![873],
            vec!["@RSYNCD:"], Some(r"@RSYNCD:\s*(\d+\.\d+)"),
            vec!["rsync-exposed"], 8),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_not_empty() {
        let rules = builtin_rules();
        assert!(rules.len() > 10, "should have substantial rule coverage");
    }

    #[test]
    fn all_rules_have_unique_ids() {
        let rules = builtin_rules();
        let mut seen = std::collections::HashSet::new();
        for rule in &rules {
            assert!(seen.insert(&rule.id), "duplicate rule id: {}", rule.id);
        }
    }

    #[test]
    fn all_rules_have_patterns() {
        for rule in builtin_rules() {
            assert!(!rule.patterns.is_empty(), "rule {} has no patterns", rule.id);
        }
    }
}
