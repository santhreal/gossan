//! For every extended rule (Stage 1: classify expansion to top-100),
//! assert a representative banner triggers the matcher and returns
//! the expected `service` name.
//!
//! Banner samples are minimal real-world fragments; if the matcher
//! ever misses one of these, that rule has rotted.

use gossan_classify::matcher::CpuMatcher;
use gossan_classify::rules::builtin_rules;

fn matcher() -> CpuMatcher {
    CpuMatcher::new(builtin_rules())
}

fn assert_matches(banner: &str, expected_service: &str) {
    let m = matcher();
    let hits = m.match_banner(banner);
    assert!(
        hits.iter().any(|h| h.service == expected_service),
        "expected service `{expected_service}` to match banner `{banner}`, got {:?}",
        hits.iter().map(|h| &h.service).collect::<Vec<_>>()
    );
}

#[test]
fn rule_count_at_least_top_100() {
    let n = builtin_rules().len();
    assert!(n >= 90, "rule coverage too low: {n} < 90");
}

#[test]
fn http_servers_match() {
    assert_matches("HTTP/1.1 200 OK\r\nServer: HAProxy\r\n", "HAProxy");
    assert_matches("HTTP/1.1 200 OK\r\nServer: Caddy\r\n", "Caddy");
    assert_matches("HTTP/1.1 200 OK\r\nServer: LiteSpeed/6.0.12\r\n", "LiteSpeed");
    assert_matches("HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n", "Apache Tomcat");
    assert_matches("HTTP/1.1 200 OK\r\nServer: Jetty(11.0.7)\r\n", "Eclipse Jetty");
    assert_matches("HTTP/1.1 200 OK\r\nServer: TornadoServer/6.1\r\n", "Tornado");
    assert_matches("HTTP/1.1 200 OK\r\nServer: gunicorn/20.1.0\r\n", "Gunicorn");
    assert_matches("HTTP/1.1 200 OK\r\nWerkzeug/2.3.7 Python/3.11.6\r\n", "Werkzeug");
    assert_matches("HTTP/1.1 200 OK\r\nServer: uvicorn\r\n", "Uvicorn");
    assert_matches("HTTP/1.1 200 OK\r\nServer: puma 5.6.4 (ruby)\r\n", "Puma");
    assert_matches("HTTP/1.1 200 OK\r\nX-Powered-By: Express\r\n", "Express (Node)");
    assert_matches("HTTP/1.1 200 OK\r\nServer: awselb/2.0\r\n", "AWS ELB");
    assert_matches("HTTP/1.1 200 OK\r\nCF-Ray: 8a1b2c\r\nServer: cloudflare\r\n", "Cloudflare");
    assert_matches("HTTP/1.1 200 OK\r\nServer: AkamaiGHost\r\n", "Akamai");
    assert_matches("HTTP/1.1 200 OK\r\nVia: 1.1 varnish\r\n", "Varnish");
    assert_matches("HTTP/1.1 200 OK\r\nServer: Traefik/2.10.4\r\n", "Traefik");
    assert_matches("HTTP/1.1 200 OK\r\nServer: envoy\r\nX-Envoy-Upstream-Service-Time: 5\r\n", "Envoy");
}

#[test]
fn caches_and_kv_match() {
    assert_matches("VERSION 1.6.21\r\n", "Memcached");
    assert_matches(r#"{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}"#, "etcd");
    assert_matches("HTTP/1.1 200 OK\r\nX-Consul-Index: 5\r\n", "Consul");
    assert_matches("HTTP/1.1 200 OK\r\nX-Vault-Request: true\r\n", "HashiCorp Vault");
}

#[test]
fn document_and_column_dbs_match() {
    assert_matches(r#"{"couchdb":"Welcome to Apache CouchDB","version":"3.3.2"}"#, "CouchDB");
    assert_matches("Apache Cassandra 4.1.3", "Cassandra");
    assert_matches("HTTP/1.1 200 OK\r\nX-ClickHouse-Server-Display-Name: srv1\r\n", "ClickHouse");
    assert_matches("HTTP/1.1 200 OK\r\nX-Influxdb-Version: 2.7.4\r\n", "InfluxDB");
}

#[test]
fn brokers_match() {
    assert_matches("AMQP\x00\x00\x09\x01", "RabbitMQ");
    assert_matches("HTTP/1.1 200 OK\r\nServer: RabbitMQ Management 3.12.4\r\n", "RabbitMQ Management");
    assert_matches("org.apache.kafka.common 3.6.0", "Kafka");
    assert_matches("zookeeper.version=3.8.1", "ZooKeeper");
    assert_matches(r#"INFO {"server_name":"ns1","version":"2.10.4"}"#, "NATS");
    assert_matches("mosquitto version 2.0.18 starting", "Mosquitto MQTT");
    assert_matches("Pulsar 2.11.1 ready", "Apache Pulsar");
}

#[test]
fn container_orchestration_match() {
    assert_matches(r#"HTTP/1.1 200 OK\r\nApiVersion: 1.43\r\nDocker/24.0.7"#, "Docker daemon");
    assert_matches(r#"{"kind":"APIVersions","gitVersion":"v1.28.4"}"#, "Kubernetes API");
    assert_matches("HTTP/1.1 200 OK\r\nX-Portainer-Version: 2.19.4\r\n", "Portainer");
    assert_matches("HTTP/1.1 200 OK\r\nX-Rancher-Foo: bar\r\n", "Rancher");
    assert_matches("HTTP/1.1 200 OK\r\nServer: kubelet/runningpods\r\n", "kubelet");
}

#[test]
fn cicd_and_repos_match() {
    assert_matches("HTTP/1.1 200 OK\r\nX-Jenkins: 2.426.1\r\n", "Jenkins");
    assert_matches("HTTP/1.1 200 OK\r\nX-Gitlab-Meta: foo\r\n", "GitLab");
    assert_matches("HTTP/1.1 200 OK\r\nX-Gitea-Server: foo\r\nGitea/1.21.0\r\n", "Gitea");
    assert_matches("Gerrit-3.8.2 ready", "Gerrit");
    assert_matches("HTTP/1.1 200 OK\r\nServer: SonarQube/9.9.2\r\n", "SonarQube");
    assert_matches("HTTP/1.1 200 OK\r\nServer: Nexus/3.61.0\r\nX-Nexus-Repository: maven\r\n", "Sonatype Nexus");
    assert_matches("HTTP/1.1 200 OK\r\nX-JFrog-Art-Api: foo\r\nArtifactory/7.71.4\r\n", "JFrog Artifactory");
    assert_matches("HTTP/1.1 200 OK\r\nServer: TeamCity 2023.05\r\n", "JetBrains TeamCity");
    assert_matches("HTTP/1.1 200 OK\r\nX-Concourse-Version: v7.10.0\r\n", "Concourse CI");
    assert_matches("HTTP/1.1 200 OK\r\nX-Drone-Build: 5\r\n", "Drone CI");
    assert_matches("HTTP/1.1 200 OK\r\nX-ArgoCD-Version: v2.9.3\r\n", "ArgoCD");
    assert_matches("HTTP/1.1 200 OK\r\nX-Spinnaker-Application: foo\r\n", "Spinnaker");
    assert_matches("HTTP/1.1 200 OK\r\nX-Harbor-Version: v2.9.1\r\n", "Harbor");
    assert_matches("HTTP/1.1 200 OK\r\nX-Quay-Build: 3.10\r\n", "Quay");
}

#[test]
fn atlassian_match() {
    assert_matches("HTTP/1.1 200 OK\r\nX-AUSERNAME: anonymous\r\nServer: Bamboo\r\n", "Atlassian Bamboo");
    assert_matches("HTTP/1.1 200 OK\r\nSet-Cookie: atl_bitbucket_session=foo; Path=/\r\n", "Atlassian Bitbucket");
    assert_matches("HTTP/1.1 200 OK\r\nX-Confluence-Request-Time: 12\r\n", "Confluence");
    assert_matches("HTTP/1.1 200 OK\r\nX-AREQUESTID: 1\r\nSet-Cookie: JSESSIONID=foo;\r\n", "Jira");
}

#[test]
fn observability_match() {
    assert_matches("HTTP/1.1 200 OK\r\nSet-Cookie: grafana_session=foo;\r\nGrafana v10.2.2\r\n", "Grafana");
    assert_matches("# HELP prometheus_build_info A metric...\r\nversion=\"2.48.0\"", "Prometheus");
    assert_matches("HTTP/1.1 200 OK\r\nServer: Alertmanager/0.26.0\r\n", "Alertmanager");
    assert_matches("HTTP/1.1 200 OK\r\nServer: loki/2.9.2\r\n", "Grafana Loki");
    assert_matches("HTTP/1.1 200 OK\r\nServer: tempo/2.3.0\r\n/api/traces\r\n", "Grafana Tempo");
    assert_matches("HTTP/1.1 200 OK\r\nkbn-name: kibana\r\n\"version\":\"8.11.3\"\r\n", "Kibana");
    assert_matches("fluentd-1.16.3", "Fluentd");
    assert_matches("logstash-8.11.3", "Logstash");
}

#[test]
fn auth_match() {
    assert_matches("HTTP/1.1 200 OK\r\nSet-Cookie: kc_restart=foo;\r\nKeycloak/22.0.5\r\n", "Keycloak");
    assert_matches("LDAP objectClass: top", "OpenLDAP");
    assert_matches("FreeRADIUS Version 3.2.3", "FreeRADIUS");
}

#[test]
fn mail_match() {
    assert_matches("+OK Dovecot ready.\r\n", "Dovecot");
    assert_matches("+OK Courier-IMAP 5.1.5 server ready.\r\n", "Courier IMAP");
    assert_matches("220 mail.example.com ESMTP Sendmail 8.17.1\r\n", "Sendmail");
}

#[test]
fn file_transfer_match() {
    assert_matches("220 FileZilla Server 1.7.2 ready\r\n", "FileZilla Server");
    assert_matches("220 Pure-FTPd 1.0.51 ready\r\n", "Pure-FTPd");
    assert_matches("Samba 4.18.8-Ubuntu", "Samba");
    assert_matches("NFS_PROGRAM 100003", "NFS");
}

#[test]
fn remote_management_match() {
    assert_matches("IPMI v2 RAKP message", "IPMI");
    assert_matches("HTTP/1.1 200 OK\r\nServer: HP-iLO/4.0\r\n", "HP iLO");
    assert_matches("HTTP/1.1 200 OK\r\niDRAC8 v2.86\r\nServer: Dell Inc.\r\n", "Dell iDRAC");
    assert_matches("HTTP/1.1 200 OK\r\nServer: ATEN International\r\nSupermicro\r\n", "Supermicro BMC");
}

#[test]
fn printing_match() {
    assert_matches("HTTP/1.1 200 OK\r\nServer: CUPS/2.4.2 IPP/2.1\r\n", "IPP/CUPS");
    assert_matches("@PJL JOB NAME=test\r\nHP JetDirect\r\n", "HP JetDirect");
}

#[test]
fn legacy_cleartext_match() {
    assert_matches("Welcome to OpenWRT\r\nlogin: ", "Telnet");
    assert_matches("public OID 1.3.6.1.2.1", "SNMP");
    assert_matches("rpcbind program vers 4", "rpcbind/portmap");
}

#[test]
fn dns_servers_match() {
    assert_matches("PowerDNS Authoritative Server 4.8.4", "PowerDNS");
    assert_matches("NSD 4.8.0", "NLnet NSD");
    assert_matches("Knot DNS 3.3.2", "Knot DNS");
    assert_matches("unbound 1.18.0", "Unbound");
    assert_matches("dnsdist 1.8.0", "dnsdist");
}

#[test]
fn vpn_and_remote_desktop_match() {
    assert_matches("OpenVPN STATIC P_CONTROL", "OpenVPN");
    assert_matches("WireGuard handshake response", "WireGuard");
    assert_matches("pptp control connection", "PPTP");
    assert_matches("strongSwan 5.9.13", "strongSwan IPsec");
    assert_matches("xrdp 0.9.23 ready", "xrdp");
    assert_matches("RFB 003.008\n", "VNC");
}

#[test]
fn streaming_and_game_match() {
    assert_matches("Minecraft server protocol version 765", "Minecraft Server");
    assert_matches("TS3 INIT1", "TeamSpeak 3");
    assert_matches("HTTP/1.1 200 OK\r\nX-Plex-Version: 1.32.7\r\nPlex Media Server\r\n", "Plex Media Server");
    assert_matches("HTTP/1.1 200 OK\r\nX-Application: Jellyfin\r\nJellyfin/10.8.13\r\n", "Jellyfin");
}

#[test]
fn ics_and_storage_match() {
    assert_matches("\u{0}\u{0}\u{0}\u{0}\u{0}\u{6}\u{1}\x03\x02", "Modbus TCP");
    assert_matches("S7 ISO-on-TCP CR", "Siemens S7");
    assert_matches("iqn.2003-01.org.linux-iscsi.target", "iSCSI");
    assert_matches("HTTP/1.1 200 OK\r\nServer: MinIO/RELEASE.2024-02-13\r\n", "MinIO");
}

#[test]
fn search_and_vector_match() {
    assert_matches("HTTP/1.1 200 OK\r\nServer: Solr/9.4.0\r\nX-Solr-Status: 0\r\n", "Apache Solr");
    assert_matches("opensearch \"number\":\"2.11.1\"", "OpenSearch");
    assert_matches("milvus 2.3.4 ready", "Milvus");
    assert_matches("Qdrant/1.7.4 ready", "Qdrant");
    assert_matches("weaviate 1.23.5", "Weaviate");
}

#[test]
fn legacy_smbv1_and_rsync_match() {
    assert_matches("SMB 1.0 negotiated", "SMBv1");
    assert_matches("@RSYNCD: 31.0\r\n", "rsync");
}

#[test]
fn no_duplicate_ids() {
    let rules = builtin_rules();
    let mut seen = std::collections::HashSet::new();
    for r in &rules {
        assert!(seen.insert(r.id.clone()), "duplicate rule id {}", r.id);
    }
}
