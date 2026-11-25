use crate::gitlab::{Api, Scheme, agent, cli_hosts};
use std::time::Duration;

/// The authorities the agent for `host` verifies that host's certificate
/// against, read back from the agent GitLab's requests are made with.
fn roots(host: &str) -> String {
    let agent = agent(host, Duration::from_secs(1));
    format!("{:?}", agent.config().tls_config().root_certs())
}

/// A self-managed instance is usually served by the organization's own
/// authority, which only the machine's store holds: checked against Mozilla's
/// roots instead, GitLab would answer `UnknownIssuer` and be unreadable. That
/// is the reported failure at `https://gitlab.suse.de`. gitlab.com needs no
/// store on the machine, so it keeps Mozilla's.
#[test]
fn a_self_managed_instance_is_verified_against_the_system() {
    for host in [
        "gitlab.suse.de",
        "gitlab.example.com",
        "GitLab.Example.COM",
        "gitlab.com.example.com",
        "gitlab.example.com:8443",
    ] {
        assert!(
            roots(host).contains("PlatformVerifier"),
            "{host} should be verified against the system's certificates"
        );
    }
    for host in ["gitlab.com", "GitLab.com", "GITLAB.COM"] {
        assert!(
            roots(host).contains("WebPki"),
            "{host} should be verified against Mozilla's certificates"
        );
    }
}

/// The host dialled decides, not the instance's name: glab may send a remote
/// on `gitlab-ssh.example.com` to that instance's `api_host`, and the
/// certificate presented is the one at the address requests go to.
#[test]
fn the_host_dialled_decides_and_the_instance_does_not() {
    let dialled = Api::new(
        "gitlab-ssh.example.com",
        Scheme::Https,
        &[cli_hosts::CliHost {
            host: "gitlab.example.com".into(),
            api_host: Some("gitlab-api.example.com".into()),
            api_protocol: None,
            ssh_host: Some("gitlab-ssh.example.com".into()),
        }],
    );
    assert_eq!(dialled.instance, "gitlab.example.com");
    assert_eq!(dialled.host, "gitlab-api.example.com");
    assert!(roots(&dialled.host).contains("PlatformVerifier"));

    // gitlab.com's own API keeps Mozilla's roots, as it needs no store on
    // the machine to be read.
    let public = Api::of_instance("gitlab.com", &[]);
    assert!(roots(&public.host).contains("WebPki"));
}
