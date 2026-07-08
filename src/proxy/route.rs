use std::collections::HashMap;

/// Where an incoming proxy request should actually go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTarget {
    /// Full upstream base URL, e.g. `https://api.anthropic.com`.
    pub upstream_base: String,
    /// Host portion of the upstream, used for domain ACL checks and audit
    /// logging, e.g. `api.anthropic.com`.
    pub domain: String,
    /// Path + query to append to `upstream_base` when forwarding.
    pub upstream_path_and_query: String,
    /// The configured upstream slug that matched (e.g. `"anthropic"`),
    /// when routing came from a provider prefix. `None` for Host-header
    /// fallback routing, which has no slug concept — cost/budget tracking
    /// (which needs a slug to price against) only applies when this is
    /// `Some`, i.e. to `wardn run`-style traffic.
    pub provider_slug: Option<String>,
}

/// Resolve where a request should be forwarded.
///
/// Two routing modes, tried in order:
///
/// 1. **Provider-prefixed routing** — if `path_and_query` starts with
///    `/{slug}/...` where `slug` is a configured upstream, the prefix is
///    stripped and the request goes to that upstream's base URL. This is
///    the mode a base-URL SDK override uses
///    (`ANTHROPIC_BASE_URL=http://127.0.0.1:7777/anthropic`), since the
///    `Host` header in that case just points back at the local proxy and
///    can't be used to pick a destination.
/// 2. **Host-header routing** — fallback for explicit forward-proxy usage
///    (e.g. `/etc/hosts` pinning + a client that sends the real API's
///    `Host` header). Preserves the original wardn behavior.
pub fn resolve_route(
    path_and_query: &str,
    host_header: &str,
    upstreams: &HashMap<String, String>,
) -> RouteTarget {
    if let Some(target) = resolve_provider_prefix(path_and_query, upstreams) {
        return target;
    }

    let domain = host_header
        .split(':')
        .next()
        .unwrap_or(host_header)
        .to_string();

    RouteTarget {
        upstream_base: format!("https://{domain}"),
        domain,
        upstream_path_and_query: path_and_query.to_string(),
        provider_slug: None,
    }
}

fn resolve_provider_prefix(
    path_and_query: &str,
    upstreams: &HashMap<String, String>,
) -> Option<RouteTarget> {
    let rest = path_and_query.strip_prefix('/')?;
    let (slug, remainder) = match rest.split_once('/') {
        Some((slug, remainder)) => (slug, remainder),
        None => (rest, ""),
    };

    let upstream_base = upstreams.get(slug)?.trim_end_matches('/').to_string();
    let domain = extract_host(&upstream_base)?;

    Some(RouteTarget {
        upstream_base,
        domain,
        upstream_path_and_query: format!("/{remainder}"),
        provider_slug: Some(slug.to_string()),
    })
}

fn extract_host(upstream_base: &str) -> Option<String> {
    let without_scheme = upstream_base
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(upstream_base);
    let host = without_scheme.split('/').next().unwrap_or(without_scheme);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstreams() -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert(
            "anthropic".to_string(),
            "https://api.anthropic.com".to_string(),
        );
        map.insert("openai".to_string(), "https://api.openai.com".to_string());
        map
    }

    #[test]
    fn test_provider_prefix_routes_to_configured_upstream() {
        let target = resolve_route("/anthropic/v1/messages", "127.0.0.1:7777", &upstreams());

        assert_eq!(target.upstream_base, "https://api.anthropic.com");
        assert_eq!(target.domain, "api.anthropic.com");
        assert_eq!(target.upstream_path_and_query, "/v1/messages");
        assert_eq!(target.provider_slug, Some("anthropic".to_string()));
    }

    #[test]
    fn test_provider_prefix_preserves_query_string() {
        let target = resolve_route("/openai/v1/models?limit=10", "127.0.0.1:7777", &upstreams());

        assert_eq!(target.upstream_path_and_query, "/v1/models?limit=10");
    }

    #[test]
    fn test_provider_prefix_bare_slug_maps_to_root() {
        let target = resolve_route("/anthropic", "127.0.0.1:7777", &upstreams());
        assert_eq!(target.upstream_path_and_query, "/");
    }

    #[test]
    fn test_unknown_prefix_falls_back_to_host_routing() {
        // "unknown" isn't a configured upstream slug, so this must NOT be
        // treated as a provider prefix — it falls back to Host routing.
        let target = resolve_route("/unknown/v1/whatever", "api.example.com", &upstreams());

        assert_eq!(target.domain, "api.example.com");
        assert_eq!(target.upstream_base, "https://api.example.com");
        assert_eq!(target.upstream_path_and_query, "/unknown/v1/whatever");
        assert_eq!(target.provider_slug, None);
    }

    #[test]
    fn test_host_header_routing_when_no_prefix_matches() {
        let target = resolve_route("/v1/chat/completions", "api.openai.com:443", &upstreams());

        assert_eq!(target.domain, "api.openai.com");
        assert_eq!(target.upstream_base, "https://api.openai.com");
        assert_eq!(target.upstream_path_and_query, "/v1/chat/completions");
        assert_eq!(target.provider_slug, None); // Host-header routing has no slug
    }

    #[test]
    fn test_base_url_override_does_not_loop_back_to_proxy() {
        // The exact bug this fixes: an SDK pointed at
        // http://127.0.0.1:7777/anthropic sends Host: 127.0.0.1:7777, which
        // must NOT resolve to the proxy itself.
        let target = resolve_route("/anthropic/v1/messages", "127.0.0.1:7777", &upstreams());

        assert_ne!(target.domain, "127.0.0.1");
        assert_eq!(target.domain, "api.anthropic.com");
    }
}
