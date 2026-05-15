#!/usr/bin/env python3
"""Fetch gitleaks.toml and convert/augment to keyhog DetectorSpec TOML."""

import re
import sys
import tomllib
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
OUT = Path(__file__).parent.parent / "rules" / "js" / "secrets.toml"

VERIFY_SPECS = {
    "github": 'verify = { service = "github", method = "GET", url = "https://api.github.com/user", headers = [{ name = "Authorization", value = "Bearer {{match}}" }], success = { status_code = 200 } }',
    "slack": 'verify = { service = "slack", method = "POST", url = "https://slack.com/api/auth.test", headers = [{ name = "Authorization", value = "Bearer {{match}}" }], success = { status_code = 200, body_contains = "\\"ok\\":true" } }',
    "stripe": 'verify = { service = "stripe", method = "GET", url = "https://api.stripe.com/v1/charges?limit=1", headers = [{ name = "Authorization", value = "Bearer {{match}}" }], success = { status_code = 200 } }',
    "sendgrid": 'verify = { service = "sendgrid", method = "GET", url = "https://api.sendgrid.com/v3/user/profile", headers = [{ name = "Authorization", value = "Bearer {{match}}" }], success = { status_code = 200 } }',
    "openai": 'verify = { service = "openai", method = "GET", url = "https://api.openai.com/v1/models", headers = [{ name = "Authorization", value = "Bearer {{match}}" }], success = { status_code = 200 } }',
}

SEVERITY_MAP = {
    "aws": "Critical",
    "github": "Critical",
    "gitlab": "Critical",
    "stripe": "Critical",
    "openai": "Critical",
    "slack": "High",
    "sendgrid": "High",
    "npm": "High",
    "private-key": "Critical",
    "generic-api-key": "Medium",
}


def fetch_gitleaks() -> dict:
    with urllib.request.urlopen(URL, timeout=60) as resp:
        data = resp.read()
    return tomllib.loads(data.decode("utf-8"))


def severity_for(id_: str, description: str) -> str:
    id_lower = id_.lower()
    for prefix, sev in SEVERITY_MAP.items():
        if prefix in id_lower:
            return sev
    desc_lower = description.lower()
    if any(w in desc_lower for w in ["private key", "secret key", "aws ", "github"]):
        return "Critical"
    if any(w in desc_lower for w in ["token", "api key", "password", "credential"]):
        return "High"
    return "Medium"


def service_for(id_: str) -> str:
    id_lower = id_.lower()
    for suffix in ["-api-key", "-access-token", "-secret", "-token", "-client-secret", "-client-id", "-password"]:
        if id_lower.endswith(suffix):
            id_lower = id_lower[: -len(suffix)]
            break
    return id_lower or "generic"


def clean_regex(r: str) -> str:
    return r.strip("'\"")


def to_keyhog_detector(rule: dict, idx: int) -> str:
    rid = rule.get("id", f"rule-{idx}")
    description = rule.get("description", "")
    regex = clean_regex(rule.get("regex", ""))
    entropy = rule.get("entropy")
    keywords = rule.get("keywords", [])
    tags = rule.get("tags", [])

    if not regex:
        return ""

    name = description or rid.replace("-", " ").title()
    severity = severity_for(rid, description)
    service = service_for(rid)

    kw_set = set(k.lower() for k in keywords)
    if not kw_set:
        m = re.search(r"\\b([A-Za-z0-9_]{2,})", regex)
        if m:
            kw_set.add(m.group(1).lower())
    kw_list = ', '.join(f'"{k}"' for k in sorted(kw_set) if k)

    entropy_line = f"# entropy threshold from gitleaks: {entropy}" if entropy else ""

    verify_block = ""
    for svc, spec in VERIFY_SPECS.items():
        if svc in rid or svc in service:
            if "client-id" not in rid and "client-secret" not in rid:
                verify_block = spec
                break

    lines = [
        f"[[detector]]",
        f'id = "{rid}"',
        f'name = "{name}"',
        f'service = "{service}"',
        f'severity = "{severity}"',
        entropy_line,
        f'keywords = [{kw_list}]',
        f'[[detector.patterns]]',
        f'regex = """{regex}"""',
    ]
    if verify_block:
        lines.append(verify_block)
    lines.append("")
    return "\n".join(lines)


EXTRA_DETECTORS = r'''
# --- Generic high-entropy strings ---
[[detector]]
id = "generic-high-entropy-base64"
name = "Generic high-entropy base64 string"
service = "generic"
severity = "Low"
keywords = ["sk_", "token", "key", "secret"]
[[detector.patterns]]
regex = """(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9+/]{40,}={0,3})['\"]?"""

[[detector]]
id = "generic-hex-token"
name = "Generic hex token"
service = "generic"
severity = "Low"
keywords = ["0x"]
[[detector.patterns]]
regex = """\b[0-9a-f]{64}\b"""

[[detector]]
id = "jwt-token"
name = "JWT Token"
service = "generic"
severity = "Medium"
keywords = ["eyJ"]
[[detector.patterns]]
regex = """eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"""

[[detector]]
id = "private-key-pem"
name = "PEM Private Key"
service = "generic"
severity = "Critical"
keywords = ["BEGIN PRIVATE", "BEGIN RSA", "BEGIN OPENSSH", "BEGIN EC"]
[[detector.patterns]]
regex = """-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]{100,500}-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"""

[[detector]]
id = "aws-secret-access-key"
name = "AWS Secret Access Key"
service = "aws"
severity = "Critical"
keywords = ["aws", "secret"]
[[detector.patterns]]
regex = """(?i)aws(?:_secret_access_key|secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"""
verify = { service = "aws", method = "GET", url = "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", headers = [{ name = "Authorization", value = "AWS4-HMAC-SHA256 Credential={{match}}/20240101/us-east-1/sts/aws4_request" }], success = { status_code = 403 } }

[[detector]]
id = "github-oauth-token"
name = "GitHub OAuth Access Token"
service = "github"
severity = "Critical"
keywords = ["gho_"]
[[detector.patterns]]
regex = """\bgho_[A-Za-z0-9_]{36}\b"""
verify = { service = "github", method = "GET", url = "https://api.github.com/user", headers = [{ name = "Authorization", value = "Bearer {{match}}" }], success = { status_code = 200 } }

[[detector]]
id = "github-app-token"
name = "GitHub App Token"
service = "github"
severity = "Critical"
keywords = ["ghs_"]
[[detector.patterns]]
regex = """\bghs_[A-Za-z0-9_]{36}\b"""
verify = { service = "github", method = "GET", url = "https://api.github.com/user", headers = [{ name = "Authorization", value = "Bearer {{match}}" }], success = { status_code = 200 } }

[[detector]]
id = "github-refresh-token"
name = "GitHub Refresh Token"
service = "github"
severity = "Critical"
keywords = ["ghr_"]
[[detector.patterns]]
regex = """\bghr_[A-Za-z0-9_]{36}\b"""

[[detector]]
id = "github-fine-grained-pat"
name = "GitHub Fine-Grained PAT"
service = "github"
severity = "Critical"
keywords = ["github_pat_"]
[[detector.patterns]]
regex = """github_pat_[A-Za-z0-9_]{22,82}\b"""
verify = { service = "github", method = "GET", url = "https://api.github.com/user", headers = [{ name = "Authorization", value = "Bearer {{match}}" }], success = { status_code = 200 } }

[[detector]]
id = "npm-access-token"
name = "NPM Access Token"
service = "npm"
severity = "High"
keywords = ["npm_"]
[[detector.patterns]]
regex = """\bnpm_[A-Za-z0-9]{36}\b"""

[[detector]]
id = "telegram-bot-api-token"
name = "Telegram Bot API Token"
service = "telegram"
severity = "High"
keywords = ["bot"]
[[detector.patterns]]
regex = """\b\d{8,10}:[A-Za-z0-9_-]{35}\b"""

[[detector]]
id = "google-cloud-api-key"
name = "Google Cloud API Key"
service = "gcp"
severity = "High"
keywords = ["AIza"]
[[detector.patterns]]
regex = """\bAIza[0-9A-Za-z\-_]{35}\b"""

[[detector]]
id = "twitter-api-key"
name = "Twitter API Key"
service = "twitter"
severity = "High"
keywords = ["twitter"]
[[detector.patterns]]
regex = """(?i)(?:twitter|x)\s*(?:api[_-]?key|consumer[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9]{25})['\"]?"""

[[detector]]
id = "twitter-api-secret"
name = "Twitter API Secret"
service = "twitter"
severity = "High"
keywords = ["twitter"]
[[detector.patterns]]
regex = """(?i)(?:twitter|x)\s*(?:api[_-]?secret|consumer[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9]{50})['\"]?"""

[[detector]]
id = "facebook-access-token"
name = "Facebook Access Token"
service = "facebook"
severity = "High"
keywords = ["EAACEdEose0cBA"]
[[detector.patterns]]
regex = """EAACEdEose0cBA[0-9A-Za-z]+"""

[[detector]]
id = "dropbox-api-key"
name = "Dropbox API Key"
service = "dropbox"
severity = "High"
keywords = ["dropbox"]
[[detector.patterns]]
regex = """(?i)dropbox\s*(?:api[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{15,})['\"]?"""

[[detector]]
id = "heroku-api-key"
name = "Heroku API Key"
service = "heroku"
severity = "High"
keywords = ["heroku"]
[[detector.patterns]]
regex = """(?i)heroku\s*api[_-]?key\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?"""

[[detector]]
id = "mailgun-api-key"
name = "Mailgun API Key"
service = "mailgun"
severity = "High"
keywords = ["mailgun"]
[[detector.patterns]]
regex = """(?i)mailgun\s*api[_-]?key\s*[:=]\s*['\"]?(key-[0-9a-f]{32})['\"]?"""

[[detector]]
id = "twilio-api-key"
name = "Twilio API Key"
service = "twilio"
severity = "High"
keywords = ["twilio"]
[[detector.patterns]]
regex = """SK[0-9a-f]{32}"""

[[detector]]
id = "paypal-client-id"
name = "PayPal Client ID"
service = "paypal"
severity = "Medium"
keywords = ["paypal"]
[[detector.patterns]]
regex = """(?i)paypal\s*client[_-]?id\s*[:=]\s*['\"]?([A-Za-z0-9_-]{80})['\"]?"""

[[detector]]
id = "paypal-secret"
name = "PayPal Secret"
service = "paypal"
severity = "High"
keywords = ["paypal"]
[[detector.patterns]]
regex = """(?i)paypal\s*(?:client[_-]?secret|secret)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{40,})['\"]?"""

[[detector]]
id = "square-access-token"
name = "Square Access Token"
service = "square"
severity = "High"
keywords = ["sq0atp"]
[[detector.patterns]]
regex = """sq0atp-[0-9A-Za-z\-_]{22,43}"""

[[detector]]
id = "square-oauth-secret"
name = "Square OAuth Secret"
service = "square"
severity = "High"
keywords = ["sq0csp"]
[[detector.patterns]]
regex = """sq0csp-[0-9A-Za-z\-_]{22,43}"""

[[detector]]
id = "shopify-api-key"
name = "Shopify API Key"
service = "shopify"
severity = "High"
keywords = ["shpat_", "shpss_", "shpca_"]
[[detector.patterns]]
regex = """(shpat_|shpss_|shpca_)[a-fA-F0-9]{32}"""

[[detector]]
id = "shopify-custom-app-token"
name = "Shopify Custom App Token"
service = "shopify"
severity = "High"
keywords = ["shpat_"]
[[detector.patterns]]
regex = """shpat_[a-fA-F0-9]{32}"""

[[detector]]
id = "shopify-shared-secret"
name = "Shopify Shared Secret"
service = "shopify"
severity = "High"
keywords = ["shpss_"]
[[detector.patterns]]
regex = """shpss_[a-fA-F0-9]{32}"""

[[detector]]
id = "dynatrace-token"
name = "Dynatrace Token"
service = "dynatrace"
severity = "High"
keywords = ["dt0c01"]
[[detector.patterns]]
regex = """dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}"""

[[detector]]
id = "mapbox-api-token"
name = "Mapbox API Token"
service = "mapbox"
severity = "High"
keywords = ["pk.eyJ1"]
[[detector.patterns]]
regex = """pk\.eyJ1Ijoi[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"""

[[detector]]
id = "discord-webhook-url"
name = "Discord Webhook URL"
service = "discord"
severity = "Medium"
keywords = ["discord"]
[[detector.patterns]]
regex = """https://discord(?:app)?\.com/api/webhooks/[0-9]{18,20}/[A-Za-z0-9_-]{60,68}"""

[[detector]]
id = "discord-bot-token"
name = "Discord Bot Token"
service = "discord"
severity = "High"
keywords = ["discord"]
[[detector.patterns]]
regex = """[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"""

[[detector]]
id = "datadog-api-key"
name = "Datadog API Key"
service = "datadog"
severity = "High"
keywords = ["datadog"]
[[detector.patterns]]
regex = """(?i)datadog\s*api[_-]?key\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?"""

[[detector]]
id = "datadog-app-key"
name = "Datadog Application Key"
service = "datadog"
severity = "High"
keywords = ["datadog"]
[[detector.patterns]]
regex = """(?i)datadog\s*app(?:lication)?[_-]?key\s*[:=]\s*['\"]?([a-f0-9]{40})['\"]?"""

[[detector]]
id = "new-relic-api-key"
name = "New Relic API Key"
service = "newrelic"
severity = "High"
keywords = ["newrelic", "NRAK"]
[[detector.patterns]]
regex = """NRAK-[A-Z0-9]{27}"""

[[detector]]
id = "new-relic-license-key"
name = "New Relic License Key"
service = "newrelic"
severity = "High"
keywords = ["newrelic"]
[[detector.patterns]]
regex = """[a-f0-9]{40}"""

[[detector]]
id = "pagerduty-integration-key"
name = "PagerDuty Integration Key"
service = "pagerduty"
severity = "High"
keywords = ["pagerduty"]
[[detector.patterns]]
regex = """[a-z0-9]{32}"""

[[detector]]
id = "pusher-app-key"
name = "Pusher App Key"
service = "pusher"
severity = "Medium"
keywords = ["pusher"]
[[detector.patterns]]
regex = """[0-9a-f]{20}"""

[[detector]]
id = "pusher-secret"
name = "Pusher Secret"
service = "pusher"
severity = "High"
keywords = ["pusher"]
[[detector.patterns]]
regex = """[0-9a-f]{32}"""

[[detector]]
id = "sentry-auth-token"
name = "Sentry Auth Token"
service = "sentry"
severity = "High"
keywords = ["sentry"]
[[detector.patterns]]
regex = """[0-9a-f]{64}"""

[[detector]]
id = "sonarqube-token"
name = "SonarQube Token"
service = "sonarqube"
severity = "High"
keywords = ["sonar"]
[[detector.patterns]]
regex = """squ_[0-9a-f]{40}"""

[[detector]]
id = "spotify-access-token"
name = "Spotify Access Token"
service = "spotify"
severity = "High"
keywords = ["spotify"]
[[detector.patterns]]
regex = """BQ[A-Za-z0-9_-]{100,200}"""

[[detector]]
id = "twitch-client-id"
name = "Twitch Client ID"
service = "twitch"
severity = "Medium"
keywords = ["twitch"]
[[detector.patterns]]
regex = """[a-z0-9]{30}"""

[[detector]]
id = "twitch-oauth-token"
name = "Twitch OAuth Token"
service = "twitch"
severity = "High"
keywords = ["twitch"]
[[detector.patterns]]
regex = """[a-z0-9]{30}"""

[[detector]]
id = "vault-token"
name = "HashiCorp Vault Token"
service = "vault"
severity = "Critical"
keywords = ["hvs.", "s.", "vault"]
[[detector.patterns]]
regex = """(hvs\.|s\.)[A-Za-z0-9]{24,100}"""

[[detector]]
id = "kubernetes-secret-token"
name = "Kubernetes Secret Token"
service = "kubernetes"
severity = "High"
keywords = ["eyJ"]
[[detector.patterns]]
regex = """eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"""

[[detector]]
id = "pypi-api-token"
name = "PyPI API Token"
service = "pypi"
severity = "High"
keywords = ["pypi"]
[[detector.patterns]]
regex = """pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{100,200}"""

[[detector]]
id = "rubygems-api-key"
name = "RubyGems API Key"
service = "rubygems"
severity = "High"
keywords = ["rubygems"]
[[detector.patterns]]
regex = """[a-f0-9]{48}"""

[[detector]]
id = "docker-hub-access-token"
name = "Docker Hub Access Token"
service = "docker"
severity = "High"
keywords = ["dckr_pat_"]
[[detector.patterns]]
regex = """dckr_pat_[A-Za-z0-9_-]{27}"""

[[detector]]
id = "digitalocean-api-token"
name = "DigitalOcean API Token"
service = "digitalocean"
severity = "High"
keywords = ["dop_v1_"]
[[detector.patterns]]
regex = """dop_v1_[a-f0-9]{64}"""

[[detector]]
id = "digitalocean-spaces-key"
name = "DigitalOcean Spaces Key"
service = "digitalocean"
severity = "High"
keywords = ["DO"]
[[detector.patterns]]
regex = """DO[A-Z0-9]{62}"""

[[detector]]
id = "algolia-api-key"
name = "Algolia API Key"
service = "algolia"
severity = "High"
keywords = ["algolia"]
[[detector.patterns]]
regex = """[0-9a-f]{32}"""

[[detector]]
id = "asana-access-token"
name = "Asana Access Token"
service = "asana"
severity = "High"
keywords = ["asana"]
[[detector.patterns]]
regex = """[0-9]{16}:[A-Za-z0-9]{32}"""

[[detector]]
id = "atlassian-api-token"
name = "Atlassian API Token"
service = "atlassian"
severity = "High"
keywords = ["atlassian"]
[[detector.patterns]]
regex = """[A-Za-z0-9]{24}"""

[[detector]]
id = "bitbucket-app-password"
name = "Bitbucket App Password"
service = "bitbucket"
severity = "High"
keywords = ["bitbucket"]
[[detector.patterns]]
regex = """[A-Za-z0-9]{32}"""

[[detector]]
id = "circleci-api-token"
name = "CircleCI API Token"
service = "circleci"
severity = "High"
keywords = ["circleci"]
[[detector.patterns]]
regex = """[0-9a-f]{40}"""

[[detector]]
id = "cloudflare-api-key"
name = "Cloudflare API Key"
service = "cloudflare"
severity = "High"
keywords = ["cloudflare"]
[[detector.patterns]]
regex = """[0-9a-f]{37}"""

[[detector]]
id = "codecov-upload-token"
name = "Codecov Upload Token"
service = "codecov"
severity = "High"
keywords = ["codecov"]
[[detector.patterns]]
regex = """[0-9a-f]{32}"""

[[detector]]
id = "coveralls-repo-token"
name = "Coveralls Repo Token"
service = "coveralls"
severity = "High"
keywords = ["coveralls"]
[[detector.patterns]]
regex = """[A-Za-z0-9]{32}\.[A-Za-z0-9_-]{43,46}"""

[[detector]]
id = "firebase-api-token"
name = "Firebase API Token"
service = "firebase"
severity = "High"
keywords = ["firebase"]
[[detector.patterns]]
regex = """1/[0-9A-Za-z_-]{43}"""

[[detector]]
id = "gitter-access-token"
name = "Gitter Access Token"
service = "gitter"
severity = "High"
keywords = ["gitter"]
[[detector.patterns]]
regex = """[a-f0-9]{40}"""

[[detector]]
id = "grafana-api-key"
name = "Grafana API Key"
service = "grafana"
severity = "High"
keywords = ["grafana"]
[[detector.patterns]]
regex = """eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"""

[[detector]]
id = "hubspot-api-key"
name = "HubSpot API Key"
service = "hubspot"
severity = "High"
keywords = ["hubspot"]
[[detector.patterns]]
regex = """[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"""

[[detector]]
id = "intercom-access-token"
name = "Intercom Access Token"
service = "intercom"
severity = "High"
keywords = ["intercom"]
[[detector.patterns]]
regex = """[a-z0-9_-]{59}"""

[[detector]]
id = "jenkins-crumb"
name = "Jenkins Crumb"
service = "jenkins"
severity = "Medium"
keywords = ["jenkins"]
[[detector.patterns]]
regex = """[0-9a-f]{32}"""

[[detector]]
id = "jfrog-api-key"
name = "JFrog API Key"
service = "jfrog"
severity = "High"
keywords = ["jfrog"]
[[detector.patterns]]
regex = """[A-Za-z0-9]{73}"""

[[detector]]
id = "launchdarkly-sdk-key"
name = "LaunchDarkly SDK Key"
service = "launchdarkly"
severity = "High"
keywords = ["launchdarkly"]
[[detector.patterns]]
regex = """sdk-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"""

[[detector]]
id = "linear-api-key"
name = "Linear API Key"
service = "linear"
severity = "High"
keywords = ["linear"]
[[detector.patterns]]
regex = """lin_api_[A-Za-z0-9]{32}"""

[[detector]]
id = "lob-api-key"
name = "Lob API Key"
service = "lob"
severity = "High"
keywords = ["lob"]
[[detector.patterns]]
regex = """live_pub_[a-f0-9]{32}"""

[[detector]]
id = "mailchimp-api-key"
name = "Mailchimp API Key"
service = "mailchimp"
severity = "High"
keywords = ["mailchimp"]
[[detector.patterns]]
regex = """[0-9a-f]{32}-us[0-9]{1,2}"""

[[detector]]
id = "mattermost-access-token"
name = "Mattermost Access Token"
service = "mattermost"
severity = "High"
keywords = ["mattermost"]
[[detector.patterns]]
regex = """[a-z0-9]{26}"""

[[detector]]
id = "messagebird-api-key"
name = "MessageBird API Key"
service = "messagebird"
severity = "High"
keywords = ["messagebird"]
[[detector.patterns]]
regex = """[A-Za-z0-9]{25}"""

[[detector]]
id = "netlify-access-token"
name = "Netlify Access Token"
service = "netlify"
severity = "High"
keywords = ["netlify"]
[[detector.patterns]]
regex = """[0-9a-zA-Z]{43,46}"""

[[detector]]
id = "notion-integration-token"
name = "Notion Integration Token"
service = "notion"
severity = "High"
keywords = ["notion"]
[[detector.patterns]]
regex = """secret_[A-Za-z0-9]{43}"""

[[detector]]
id = "plaid-client-id"
name = "Plaid Client ID"
service = "plaid"
severity = "Medium"
keywords = ["plaid"]
[[detector.patterns]]
regex = """[0-9a-f]{24}"""

[[detector]]
id = "plaid-secret"
name = "Plaid Secret"
service = "plaid"
severity = "High"
keywords = ["plaid"]
[[detector.patterns]]
regex = """[0-9a-f]{32}"""

[[detector]]
id = "postman-api-key"
name = "Postman API Key"
service = "postman"
severity = "High"
keywords = ["postman"]
[[detector.patterns]]
regex = """PMAK-[a-f0-9]{24}-[a-f0-9]{34}"""

[[detector]]
id = "pubnub-publish-key"
name = "PubNub Publish Key"
service = "pubnub"
severity = "Medium"
keywords = ["pubnub"]
[[detector.patterns]]
regex = """pub-c-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"""

[[detector]]
id = "pubnub-subscribe-key"
name = "PubNub Subscribe Key"
service = "pubnub"
severity = "Medium"
keywords = ["pubnub"]
[[detector.patterns]]
regex = """sub-c-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"""

[[detector]]
id = "pulumi-access-token"
name = "Pulumi Access Token"
service = "pulumi"
severity = "High"
keywords = ["pulumi"]
[[detector.patterns]]
regex = """pul-[a-f0-9]{40}"""

[[detector]]
id = "readme-api-key"
name = "ReadMe API Key"
service = "readme"
severity = "High"
keywords = ["readme"]
[[detector.patterns]]
regex = """rdme_[a-z0-9]{70}"""

[[detector]]
id = "samsara-api-token"
name = "Samsara API Token"
service = "samsara"
severity = "High"
keywords = ["samsara"]
[[detector.patterns]]
regex = """samsara_[a-zA-Z0-9]{40,120}"""

[[detector]]
id = "segment-write-key"
name = "Segment Write Key"
service = "segment"
severity = "High"
keywords = ["segment"]
[[detector.patterns]]
regex = """[0-9a-zA-Z]{32}"""

[[detector]]
id = "shippo-api-token"
name = "Shippo API Token"
service = "shippo"
severity = "High"
keywords = ["shippo"]
[[detector.patterns]]
regex = """shippo_(live|test)_[a-f0-9]{40}"""

[[detector]]
id = "snyk-api-token"
name = "Snyk API Token"
service = "snyk"
severity = "High"
keywords = ["snyk"]
[[detector.patterns]]
regex = """[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"""

[[detector]]
id = "stripe-restricted-key"
name = "Stripe Restricted Key"
service = "stripe"
severity = "Critical"
keywords = ["rk_live_", "rk_test_"]
[[detector.patterns]]
regex = """r[sk]_(live|test)_[0-9a-zA-Z]{24,}"""
verify = { service = "stripe", method = "GET", url = "https://api.stripe.com/v1/charges?limit=1", headers = [{ name = "Authorization", value = "Bearer {{match}}" }], success = { status_code = 200 } }

[[detector]]
id = "travis-ci-access-token"
name = "Travis CI Access Token"
service = "travisci"
severity = "High"
keywords = ["travis"]
[[detector.patterns]]
regex = """[0-9a-zA-Z]{22}"""

[[detector]]
id = "wakatime-api-key"
name = "WakaTime API Key"
service = "wakatime"
severity = "High"
keywords = ["wakatime"]
[[detector.patterns]]
regex = """waka_[a-f0-9]{32}"""

[[detector]]
id = "wasm-aws-access-key"
name = "AWS Access Key in WASM"
service = "aws"
severity = "Critical"
keywords = ["AKIA"]
[[detector.patterns]]
regex = """AKIA[0-9A-Z]{16}"""

[[detector]]
id = "wasm-gcp-api-key"
name = "GCP API Key in WASM"
service = "gcp"
severity = "High"
keywords = ["AIza"]
[[detector.patterns]]
regex = """AIza[0-9A-Za-z\-_]{35}"""

[[detector]]
id = "wasm-github-token"
name = "GitHub Token in WASM"
service = "github"
severity = "Critical"
keywords = ["ghp_"]
[[detector.patterns]]
regex = """ghp_[a-zA-Z0-9]{36}"""

[[detector]]
id = "wasm-openai-key"
name = "OpenAI API Key in WASM"
service = "openai"
severity = "Critical"
keywords = ["sk-"]
[[detector.patterns]]
regex = """sk-[a-zA-Z0-9]{48}"""

[[detector]]
id = "wasm-stripe-key"
name = "Stripe Secret Key in WASM"
service = "stripe"
severity = "Critical"
keywords = ["sk_live_"]
[[detector.patterns]]
regex = """sk_live_[0-9a-zA-Z]{24,}"""

[[detector]]
id = "wasm-slack-token"
name = "Slack Token in WASM"
service = "slack"
severity = "High"
keywords = ["xox"]
[[detector.patterns]]
regex = """xox[baprs]-[0-9a-zA-Z\-]{10,48}"""

[[detector]]
id = "wasm-sendgrid-key"
name = "SendGrid Key in WASM"
service = "sendgrid"
severity = "High"
keywords = ["SG."]
[[detector.patterns]]
regex = """SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}"""

[[detector]]
id = "wasm-npm-token"
name = "NPM Token in WASM"
service = "npm"
severity = "High"
keywords = ["npm_"]
[[detector.patterns]]
regex = """npm_[a-zA-Z0-9]{36}"""

[[detector]]
id = "wasm-private-key"
name = "Private Key in WASM"
service = "generic"
severity = "Critical"
keywords = ["PRIVATE KEY"]
[[detector.patterns]]
regex = """-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"""

[[detector]]
id = "wasm-internal-url"
name = "Internal URL in WASM"
service = "generic"
severity = "High"
keywords = ["localhost", "127.0.0.1", "192.168"]
[[detector.patterns]]
regex = """https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[:/]"""

[[detector]]
id = "js-fetch-endpoint"
name = "JS Fetch Endpoint"
service = "generic"
severity = "Info"
keywords = ["fetch"]
[[detector.patterns]]
regex = """fetch\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"""

[[detector]]
id = "js-axios-get"
name = "JS Axios GET Endpoint"
service = "generic"
severity = "Info"
keywords = [".get("]
[[detector.patterns]]
regex = """\.get\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"""

[[detector]]
id = "js-axios-post"
name = "JS Axios POST Endpoint"
service = "generic"
severity = "Info"
keywords = [".post("]
[[detector.patterns]]
regex = """\.post\(["'`]([^"'`\s<>{}\[\]]{1,200})["'`]"""

[[detector]]
id = "js-api-path"
name = "JS API Path"
service = "generic"
severity = "Info"
keywords = ["/api/", "/v1/", "/graphql"]
[[detector.patterns]]
regex = """["'`](/(?:api|v\d+|graphql|rest|rpc|internal|admin|auth|user|account|data|search|webhook|health|metrics|status)[^"'`\s<>{}\[\]]{0,200})["'`]"""
'''


MORE_DETECTORS = r'''
# --- Batch 2: additional SaaS / cloud / CI / messaging ---
[[detector]]
id = "airtable-api-key"
name = "Airtable API Key"
service = "airtable"
severity = "High"
keywords = ["airtable"]
[[detector.patterns]]
regex = """key[a-zA-Z0-9]{14}"""

[[detector]]
id = "algolia-admin-key"
name = "Algolia Admin API Key"
service = "algolia"
severity = "Critical"
keywords = ["algolia"]
[[detector.patterns]]
regex = """[0-9a-f]{32}"""

[[detector]]
id = "amplitude-api-key"
name = "Amplitude API Key"
service = "amplitude"
severity = "Medium"
keywords = ["amplitude"]
[[detector.patterns]]
regex = """[a-f0-9]{32}"""

[[detector]]
id = "auth0-client-secret"
name = "Auth0 Client Secret"
service = "auth0"
severity = "High"
keywords = ["auth0"]
[[detector.patterns]]
regex = """[a-zA-Z0-9_-]{64}"""

[[detector]]
id = "aws-session-token"
name = "AWS Session Token"
service = "aws"
severity = "Critical"
keywords = ["FwoGZXIvYXdzE"]
[[detector.patterns]]
regex = """FwoGZXIvYXdzE[A-Za-z0-9/+=]{200,}"""

[[detector]]
id = "azure-active-directory-token"
name = "Azure Active Directory Token"
service = "azure"
severity = "Critical"
keywords = ["eyJ0eX"]
[[detector.patterns]]
regex = """eyJ0eX[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"""

[[detector]]
id = "azure-devops-pat"
name = "Azure DevOps Personal Access Token"
service = "azure"
severity = "High"
keywords = ["azure"]
[[detector.patterns]]
regex = """[a-z0-9]{52}"""

[[detector]]
id = "azure-subscription-key"
name = "Azure Subscription Key"
service = "azure"
severity = "High"
keywords = ["azure"]
[[detector.patterns]]
regex = """[a-f0-9]{32}"""

[[detector]]
id = "beamer-api-key"
name = "Beamer API Key"
service = "beamer"
severity = "High"
keywords = ["beamer"]
[[detector.patterns]]
regex = """b_[a-zA-Z0-9]{24}"""

[[detector]]
id = "bittrex-api-key"
name = "Bittrex API Key"
service = "bittrex"
severity = "High"
keywords = ["bittrex"]
[[detector.patterns]]
regex = """[a-f0-9]{32}"""

[[detector]]
id = "bittrex-secret-key"
name = "Bittrex Secret Key"
service = "bittrex"
severity = "High"
keywords = ["bittrex"]
[[detector.patterns]]
regex = """[a-f0-9]{32}"""

[[detector]]
id = "browserstack-access-key"
name = "BrowserStack Access Key"
service = "browserstack"
severity = "High"
keywords = ["browserstack"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{20}"""

[[detector]]
id = "buildkite-api-token"
name = "Buildkite API Access Token"
service = "buildkite"
severity = "High"
keywords = ["buildkite"]
[[detector.patterns]]
regex = """[a-z0-9]{40}"""

[[detector]]
id = "buttercms-api-token"
name = "ButterCMS API Token"
service = "buttercms"
severity = "High"
keywords = ["buttercms"]
[[detector.patterns]]
regex = """[a-z0-9]{40}"""

[[detector]]
id = "cisco-webex-token"
name = "Cisco Webex Token"
service = "webex"
severity = "High"
keywords = ["webex"]
[[detector.patterns]]
regex = """[A-Za-z0-9_-]{83}"""

[[detector]]
id = "clojars-deploy-token"
name = "Clojars Deploy Token"
service = "clojars"
severity = "High"
keywords = ["clojars"]
[[detector.patterns]]
regex = """CLOJARS_[a-z0-9]{60}"""

[[detector]]
id = "contentful-delivery-api"
name = "Contentful Delivery API"
service = "contentful"
severity = "High"
keywords = ["contentful"]
[[detector.patterns]]
regex = """[a-zA-Z0-9_-]{43}"""

[[detector]]
id = "contentful-management-api"
name = "Contentful Management API"
service = "contentful"
severity = "High"
keywords = ["contentful"]
[[detector.patterns]]
regex = """CFPAT-[a-zA-Z0-9_-]{43}"""

[[detector]]
id = "databricks-api-token"
name = "Databricks API Token"
service = "databricks"
severity = "High"
keywords = ["databricks"]
[[detector.patterns]]
regex = """dapi[a-f0-9]{32}"""

[[detector]]
id = "deepl-api-key"
name = "DeepL API Key"
service = "deepl"
severity = "High"
keywords = ["deepl"]
[[detector.patterns]]
regex = """[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:fx"""

[[detector]]
id = "deviantart-secret"
name = "DeviantArt Secret"
service = "deviantart"
severity = "High"
keywords = ["deviantart"]
[[detector.patterns]]
regex = """[a-f0-9]{32}"""

[[detector]]
id = "doppler-api-key"
name = "Doppler API Key"
service = "doppler"
severity = "High"
keywords = ["dp.pt"]
[[detector.patterns]]
regex = """dp\.pt\.[a-zA-Z0-9]{43}"""

[[detector]]
id = "dropbox-short-lived-token"
name = "Dropbox Short Lived Access Token"
service = "dropbox"
severity = "High"
keywords = ["sl."]
[[detector.patterns]]
regex = """sl\.[a-zA-Z0-9_-]{140}"""

[[detector]]
id = "duffel-api-token"
name = "Duffel API Token"
service = "duffel"
severity = "High"
keywords = ["duffel"]
[[detector.patterns]]
regex = """duffel_test_[a-zA-Z0-9_-]{43}"""

[[detector]]
id = "dynadmin-password"
name = "DynAdmin Password"
service = "dynadmin"
severity = "High"
keywords = ["dynadmin"]
[[detector.patterns]]
regex = """(?i)dynadmin[_-]?password\s*[:=]\s*['\"]?([^\s'\"]+)['\"]?"""

[[detector]]
id = "easypost-api-token"
name = "EasyPost API Token"
service = "easypost"
severity = "High"
keywords = ["EZAK"]
[[detector.patterns]]
regex = """EZAK[a-zA-Z0-9]{54}"""

[[detector]]
id = "etsy-api-key"
name = "Etsy API Key"
service = "etsy"
severity = "High"
keywords = ["etsy"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{24}"""

[[detector]]
id = "facebook-app-secret"
name = "Facebook App Secret"
service = "facebook"
severity = "High"
keywords = ["facebook"]
[[detector.patterns]]
regex = """[a-f0-9]{32}"""

[[detector]]
id = "fastly-api-token"
name = "Fastly API Token"
service = "fastly"
severity = "High"
keywords = ["fastly"]
[[detector.patterns]]
regex = """[a-zA-Z0-9_-]{32}"""

[[detector]]
id = "finnhub-api-key"
name = "Finnhub API Key"
service = "finnhub"
severity = "High"
keywords = ["finnhub"]
[[detector.patterns]]
regex = """[a-z0-9]{20}"""

[[detector]]
id = "flask-secret-key"
name = "Flask Secret Key"
service = "flask"
severity = "High"
keywords = ["flask"]
[[detector.patterns]]
regex = """(?i)secret[_-]?key\s*[:=]\s*['\"]?([^\s'\"]+)['\"]?"""

[[detector]]
id = "flickr-api-key"
name = "Flickr API Key"
service = "flickr"
severity = "High"
keywords = ["flickr"]
[[detector.patterns]]
regex = """[a-f0-9]{32}"""

[[detector]]
id = "flutterwave-secret-key"
name = "Flutterwave Secret Key"
service = "flutterwave"
severity = "High"
keywords = ["flutterwave"]
[[detector.patterns]]
regex = """FLWSECK-[a-z0-9_-]{32}-X"""

[[detector]]
id = "frameio-api-token"
name = "Frame.io API Token"
service = "frameio"
severity = "High"
keywords = ["frameio"]
[[detector.patterns]]
regex = """fio-u-[a-zA-Z0-9_-]{43}"""

[[detector]]
id = "freshdesk-api-key"
name = "Freshdesk API Key"
service = "freshdesk"
severity = "High"
keywords = ["freshdesk"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{20}"""

[[detector]]
id = "fullstory-api-key"
name = "FullStory API Key"
service = "fullstory"
severity = "High"
keywords = ["fullstory"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{24}"""

[[detector]]
id = "gcp-service-account"
name = "GCP Service Account Key"
service = "gcp"
severity = "Critical"
keywords = ["type", "service_account"]
[[detector.patterns]]
regex = """\"type\":\s*\"service_account\""""

[[detector]]
id = "generic-password-assignment"
name = "Generic Password Assignment"
service = "generic"
severity = "Medium"
keywords = ["password"]
[[detector.patterns]]
regex = """(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?"""

[[detector]]
id = "generic-secret-assignment"
name = "Generic Secret Assignment"
service = "generic"
severity = "Medium"
keywords = ["secret"]
[[detector.patterns]]
regex = """(?i)(?:secret|api[_-]?key|auth[_-]?token)\s*[:=]\s*['\"]?([^\s'\"]{16,})['\"]?"""

[[detector]]
id = "generic-token-bearer"
name = "Generic Bearer Token"
service = "generic"
severity = "Medium"
keywords = ["bearer"]
[[detector.patterns]]
regex = """(?i)bearer\s+[a-zA-Z0-9_\-\.=]{20,}"""

[[detector]]
id = "github-app-private-key"
name = "GitHub App Private Key"
service = "github"
severity = "Critical"
keywords = ["BEGIN RSA PRIVATE KEY"]
[[detector.patterns]]
regex = """-----BEGIN RSA PRIVATE KEY-----[\s\S]{200,}-----END RSA PRIVATE KEY-----"""

[[detector]]
id = "google-oauth-client-secret"
name = "Google OAuth Client Secret"
service = "google"
severity = "High"
keywords = ["google"]
[[detector.patterns]]
regex = """[a-zA-Z0-9_-]{24}"""

[[detector]]
id = "gradle-signing-key"
name = "Gradle Signing Key"
service = "gradle"
severity = "High"
keywords = ["gradle"]
[[detector.patterns]]
regex = """[A-Za-z0-9/+=]{40}"""

[[detector]]
id = "groovy-eval"
name = "Groovy Eval Script"
service = "generic"
severity = "Medium"
keywords = ["eval"]
[[detector.patterns]]
regex = """eval\s*\(\s*['\"]"""

[[detector]]
id = "harness-api-key"
name = "Harness API Key"
service = "harness"
severity = "High"
keywords = ["harness"]
[[detector.patterns]]
regex = """[a-zA-Z0-9_-]{32}"""

[[detector]]
id = "hashicorp-nomad-token"
name = "HashiCorp Nomad Token"
service = "nomad"
severity = "Critical"
keywords = ["nomad"]
[[detector.patterns]]
regex = """[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"""

[[detector]]
id = "honeycomb-api-key"
name = "Honeycomb API Key"
service = "honeycomb"
severity = "High"
keywords = ["honeycomb"]
[[detector.patterns]]
regex = """[a-f0-9]{32}"""

[[detector]]
id = "huggingface-token"
name = "Hugging Face Token"
service = "huggingface"
severity = "High"
keywords = ["hf_"]
[[detector.patterns]]
regex = """hf_[a-zA-Z0-9_-]{39}"""

[[detector]]
id = "infracost-api-key"
name = "Infracost API Key"
service = "infracost"
severity = "High"
keywords = ["ico-"]
[[detector.patterns]]
regex = """ico-[a-zA-Z0-9_-]{32}"""

[[detector]]
id = "invision-api-token"
name = "InVision API Token"
service = "invision"
severity = "High"
keywords = ["invision"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{24}"""

[[detector]]
id = "jetbrains-hub-token"
name = "JetBrains Hub Token"
service = "jetbrains"
severity = "High"
keywords = ["jetbrains"]
[[detector.patterns]]
regex = """[a-zA-Z0-9_-]{64}"""

[[detector]]
id = "kraken-api-key"
name = "Kraken API Key"
service = "kraken"
severity = "High"
keywords = ["kraken"]
[[detector.patterns]]
regex = """[a-zA-Z0-9/+=]{56}"""

[[detector]]
id = "kucoin-api-key"
name = "Kucoin API Key"
service = "kucoin"
severity = "High"
keywords = ["kucoin"]
[[detector.patterns]]
regex = """[a-f0-9]{24}"""

[[detector]]
id = "lodash-template-eval"
name = "Lodash Template Eval"
service = "generic"
severity = "Medium"
keywords = ["_.template"]
[[detector.patterns]]
regex = """_.template\s*\("""

[[detector]]
id = "looker-api3-client-id"
name = "Looker API3 Client ID"
service = "looker"
severity = "Medium"
keywords = ["looker"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{20}"""

[[detector]]
id = "looker-api3-key"
name = "Looker API3 Key"
service = "looker"
severity = "High"
keywords = ["looker"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{20}"""

[[detector]]
id = "mailjet-api-key"
name = "Mailjet API Key"
service = "mailjet"
severity = "High"
keywords = ["mailjet"]
[[detector.patterns]]
regex = """[a-f0-9]{32}"""

[[detector]]
id = "maxmind-license-key"
name = "MaxMind License Key"
service = "maxmind"
severity = "High"
keywords = ["maxmind"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{16}"""

[[detector]]
id = "metabase-secret-key"
name = "Metabase Secret Key"
service = "metabase"
severity = "High"
keywords = ["metabase"]
[[detector.patterns]]
regex = """[a-f0-9]{64}"""

[[detector]]
id = "mixpanel-api-token"
name = "Mixpanel API Token"
service = "mixpanel"
severity = "High"
keywords = ["mixpanel"]
[[detector.patterns]]
regex = """[a-f0-9]{32}"""

[[detector]]
id = "mlflow-tracking-password"
name = "MLflow Tracking Password"
service = "mlflow"
severity = "High"
keywords = ["mlflow"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{20}"""

[[detector]]
id = "mongodb-connection-string"
name = "MongoDB Connection String"
service = "mongodb"
severity = "High"
keywords = ["mongodb"]
[[detector.patterns]]
regex = """mongodb(\+srv)?://[^\s\"']+"""

[[detector]]
id = "mysql-connection-string"
name = "MySQL Connection String"
service = "mysql"
severity = "High"
keywords = ["mysql"]
[[detector.patterns]]
regex = """mysql://[^\s\"']+"""

[[detector]]
id = "neo4j-auth"
name = "Neo4j Auth Credentials"
service = "neo4j"
severity = "High"
keywords = ["neo4j"]
[[detector.patterns]]
regex = """neo4j:[^\s@\"']+@[^\s\"']+"""

[[detector]]
id = "ngrok-auth-token"
name = "Ngrok Auth Token"
service = "ngrok"
severity = "High"
keywords = ["ngrok"]
[[detector.patterns]]
regex = """[a-zA-Z0-9_]{24}"""

[[detector]]
id = "npm-auth-token"
name = "NPM Auth Token"
service = "npm"
severity = "High"
keywords = ["npm_"]
[[detector.patterns]]
regex = """npm_[a-zA-Z0-9]{36}"""

[[detector]]
id = "okta-api-token"
name = "Okta API Token"
service = "okta"
severity = "Critical"
keywords = ["okta"]
[[detector.patterns]]
regex = """00[a-zA-Z0-9_-]{40}"""

[[detector]]
id = "openai-organization-id"
name = "OpenAI Organization ID"
service = "openai"
severity = "Medium"
keywords = ["org-"]
[[detector.patterns]]
regex = """org-[a-zA-Z0-9]{24}"""

[[detector]]
id = "pagerduty-api-key"
name = "PagerDuty API Key"
service = "pagerduty"
severity = "High"
keywords = ["pagerduty"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{20}"""

[[detector]]
id = "pandas-secret"
name = "Pandas Secret"
service = "generic"
severity = "Medium"
keywords = ["pandas"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{20}"""

[[detector]]
id = "paypal-braintree-access-token"
name = "PayPal Braintree Access Token"
service = "paypal"
severity = "High"
keywords = ["access_token"]
[[detector.patterns]]
regex = """access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}"""

[[detector]]
id = "pgp-private-key"
name = "PGP Private Key"
service = "generic"
severity = "Critical"
keywords = ["BEGIN PGP PRIVATE KEY"]
[[detector.patterns]]
regex = """-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{100,}-----END PGP PRIVATE KEY BLOCK-----"""

[[detector]]
id = "planetscale-api-key"
name = "PlanetScale API Key"
service = "planetscale"
severity = "High"
keywords = ["pscale"]
[[detector.patterns]]
regex = """pscale_[a-zA-Z0-9_-]{43}"""

[[detector]]
id = "postgresql-connection-string"
name = "PostgreSQL Connection String"
service = "postgresql"
severity = "High"
keywords = ["postgresql", "postgres"]
[[detector.patterns]]
regex = """postgres(ql)?://[^\s\"']+"""

[[detector]]
id = "postman-environment"
name = "Postman Environment Secret"
service = "postman"
severity = "High"
keywords = ["postman"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{32}"""

[[detector]]
id = "pulumi-refresh-token"
name = "Pulumi Refresh Token"
service = "pulumi"
severity = "High"
keywords = ["pulumi"]
[[detector.patterns]]
regex = """[a-f0-9]{64}"""

[[detector]]
id = "pypi-upload-token"
name = "PyPI Upload Token"
service = "pypi"
severity = "High"
keywords = ["pypi"]
[[detector.patterns]]
regex = """pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{100,200}"""

[[detector]]
id = "razorpay-api-key"
name = "Razorpay API Key"
service = "razorpay"
severity = "High"
keywords = ["rzp_"]
[[detector.patterns]]
regex = """rzp_(live|test)_[a-zA-Z0-9]{14}"""

[[detector]]
id = "redis-connection-string"
name = "Redis Connection String"
service = "redis"
severity = "High"
keywords = ["redis"]
[[detector.patterns]]
regex = """redis://[^\s\"']+"""

[[detector]]
id = "rockset-api-key"
name = "Rockset API Key"
service = "rockset"
severity = "High"
keywords = ["rockset"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{40}"""

[[detector]]
id = "salesforce-api-key"
name = "Salesforce API Key"
service = "salesforce"
severity = "High"
keywords = ["salesforce"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{15}"""

[[detector]]
id = "sauce-labs-access-key"
name = "Sauce Labs Access Key"
service = "saucelabs"
severity = "High"
keywords = ["saucelabs"]
[[detector.patterns]]
regex = """[a-f0-9-]{36}"""

[[detector]]
id = "sentry-dsn"
name = "Sentry DSN"
service = "sentry"
severity = "Medium"
keywords = ["sentry"]
[[detector.patterns]]
regex = """https://[a-f0-9]{32}@[a-z0-9.-]+\.[a-z]{2,}/\d+"""

[[detector]]
id = "shodan-api-key"
name = "Shodan API Key"
service = "shodan"
severity = "High"
keywords = ["shodan"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{32}"""

[[detector]]
id = "slack-webhook-url"
name = "Slack Webhook URL"
service = "slack"
severity = "Medium"
keywords = ["hooks.slack.com"]
[[detector.patterns]]
regex = """https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{10,}/[a-zA-Z0-9_]{24}"""

[[detector]]
id = "snowflake-connection-string"
name = "Snowflake Connection String"
service = "snowflake"
severity = "High"
keywords = ["snowflake"]
[[detector.patterns]]
regex = """snowflake://[^\s\"']+"""

[[detector]]
id = "splunk-hec-token"
name = "Splunk HEC Token"
service = "splunk"
severity = "High"
keywords = ["splunk"]
[[detector.patterns]]
regex = """[a-f0-9-]{36}"""

[[detector]]
id = "spring-boot-actuator-password"
name = "Spring Boot Actuator Password"
service = "spring"
severity = "High"
keywords = ["spring"]
[[detector.patterns]]
regex = """(?i)spring[_-]?security[_-]?user[_-]?password\s*[:=]\s*['\"]?([^\s'\"]+)['\"]?"""

[[detector]]
id = "squarespace-api-key"
name = "Squarespace API Key"
service = "squarespace"
severity = "High"
keywords = ["squarespace"]
[[detector.patterns]]
regex = """[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"""

[[detector]]
id = "sumologic-access-id"
name = "Sumo Logic Access ID"
service = "sumologic"
severity = "High"
keywords = ["sumologic"]
[[detector.patterns]]
regex = """su[a-zA-Z0-9]{14}"""

[[detector]]
id = "sumologic-access-key"
name = "Sumo Logic Access Key"
service = "sumologic"
severity = "High"
keywords = ["sumologic"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{64}"""

[[detector]]
id = "teamcity-api-token"
name = "TeamCity API Token"
service = "teamcity"
severity = "High"
keywords = ["teamcity"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{40}"""

[[detector]]
id = "travisci-token"
name = "Travis CI Token"
service = "travisci"
severity = "High"
keywords = ["travis"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{22}"""

[[detector]]
id = "twilio-api-secret"
name = "Twilio API Secret"
service = "twilio"
severity = "High"
keywords = ["twilio"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{32}"""

[[detector]]
id = "twitch-access-token"
name = "Twitch Access Token"
service = "twitch"
severity = "High"
keywords = ["twitch"]
[[detector.patterns]]
regex = """[a-z0-9]{30}"""

[[detector]]
id = "twitter-access-token"
name = "Twitter Access Token"
service = "twitter"
severity = "High"
keywords = ["twitter"]
[[detector.patterns]]
regex = """[0-9]{18}-[a-zA-Z0-9]{40}"""

[[detector]]
id = "twitter-access-secret"
name = "Twitter Access Secret"
service = "twitter"
severity = "High"
keywords = ["twitter"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{45}"""

[[detector]]
id = "unity-cloud-api-key"
name = "Unity Cloud API Key"
service = "unity"
severity = "High"
keywords = ["unity"]
[[detector.patterns]]
regex = """[a-f0-9]{32}"""

[[detector]]
id = "victorops-api-key"
name = "VictorOps API Key"
service = "victorops"
severity = "High"
keywords = ["victorops"]
[[detector.patterns]]
regex = """[a-f0-9]{32}"""

[[detector]]
id = "wordpress-api-key"
name = "WordPress API Key"
service = "wordpress"
severity = "High"
keywords = ["wordpress"]
[[detector.patterns]]
regex = """[a-f0-9]{32}"""

[[detector]]
id = "yandex-api-key"
name = "Yandex API Key"
service = "yandex"
severity = "High"
keywords = ["yandex"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{33}"""

[[detector]]
id = "yelp-api-key"
name = "Yelp API Key"
service = "yelp"
severity = "High"
keywords = ["yelp"]
[[detector.patterns]]
regex = """[a-zA-Z0-9_-]{128}"""

[[detector]]
id = "zendesk-api-token"
name = "Zendesk API Token"
service = "zendesk"
severity = "High"
keywords = ["zendesk"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{40}"""

[[detector]]
id = "zoom-api-key"
name = "Zoom API Key"
service = "zoom"
severity = "High"
keywords = ["zoom"]
[[detector.patterns]]
regex = """[a-zA-Z0-9_-]{22}"""

[[detector]]
id = "zoom-api-secret"
name = "Zoom API Secret"
service = "zoom"
severity = "High"
keywords = ["zoom"]
[[detector.patterns]]
regex = """[a-zA-Z0-9_-]{32}"""

[[detector]]
id = "zulip-api-key"
name = "Zulip API Key"
service = "zulip"
severity = "High"
keywords = ["zulip"]
[[detector.patterns]]
regex = """[a-zA-Z0-9]{32}"""
'''


def main() -> int:
    print("Fetching gitleaks.toml...")
    try:
        gitleaks = fetch_gitleaks()
    except Exception as e:
        print(f"Failed to fetch gitleaks.toml: {e}")
        return 1

    rules = gitleaks.get("rules", [])
    output_lines = [
        '# Auto-generated from gitleaks config + custom augmentations',
        '# DO NOT EDIT MANUALLY — run scripts/gen_gitleaks_rules.py to regenerate',
        '',
    ]

    count = 0
    for i, rule in enumerate(rules):
        det = to_keyhog_detector(rule, i)
        if det:
            output_lines.append(det)
            count += 1

    output_lines.append(EXTRA_DETECTORS.strip())
    output_lines.append(MORE_DETECTORS.strip())

    extra_count = EXTRA_DETECTORS.strip().count("[[detector]]") + MORE_DETECTORS.strip().count("[[detector]]")
    total = count + extra_count

    OUT.write_text("\n".join(output_lines), encoding="utf-8")
    print(f"Wrote {OUT} with {count} gitleaks detectors + {extra_count} custom = {total} total detectors.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
