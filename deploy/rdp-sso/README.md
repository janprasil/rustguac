# Cloudflare Access SSO for Windows RDP

In Coolify, use a Docker Compose resource sourced from this repository and set the Compose file to `compose.rdp-sso.yaml`. Run one rustguac replica so launches and password rotations for each account are serialized. Cloudflare Access signs the user in before the Quick Connect page lists their RDP destinations.

## Cloudflare and Entra ID

1. In the Entra app registration used by Cloudflare, define an App Role for Users/Groups and assign it in Enterprise Applications. Use its **Value**, for example `RemoteDesktop`, as `CF_REQUIRED_ROLE`.
2. Use only the intended Entra tenant as the login provider for the self-hosted Access application. Add `roles`, `oid`, and `tid` to the provider's custom OIDC claims. Check that the **application JWT** delivered to the origin includes them under `custom`. Test with an allowed and a denied test user before enabling access to the Windows host.
3. Set `TUNNEL_TOKEN`, `CF_ACCESS_TEAM_DOMAIN`, `CF_ENTRA_TENANT_ID`, and `CF_REQUIRED_ROLE` in Coolify. Use the HTTPS team origin as `CF_ACCESS_TEAM_DOMAIN`. Leave public ports and Coolify proxy domains unset for every service in this stack.

## Use one public address with Quick Connect

Publish `autordp.performance4.cz` through Cloudflare Tunnel and protect it with one self-hosted Access application. Set **HTTP Host Header** in the Tunnel to `autordp.performance4.cz` and point it to `http://rustguac:8080`.

Add an entry to `RDP_TARGETS` for every allowed destination. Use the same `public_host` and `access_aud` in these entries. The `connect_to` value is the exact value accepted in the public URL. Only the corresponding `target_host` from the configuration is passed to guacd.

```json
[
  {"public_host":"autordp.performance4.cz","connect_to":"10.0.0.1","target_host":"10.0.0.1","access_aud":"AUTORDP_AUD","label":"Accounting"},
  {"public_host":"autordp.performance4.cz","connect_to":"10.0.0.2","target_host":"10.0.0.2","access_aud":"AUTORDP_AUD","label":"Office"}
]
```

After redeploying, open `https://autordp.performance4.cz/?quickConnect`. The page lists configured RDP destinations for this hostname and attempts automatic sign-in when the user selects one. The optional `label` sets the displayed name.

On a connection error, the user can provide their Windows password for that session. This fallback uses the portion of the verified Entra email before `@` as the existing Windows login in `AD_DOMAIN`. It sends the password to the selected RDP server through guacd for NLA. It performs no AD writes and stores no password in Vault.

The direct link `https://autordp.performance4.cz/?connectTo=10.0.0.1` launches the first desktop automatically. An unconfigured `connectTo` returns 404. If you want the bare URL to launch a default desktop, include one entry for that public hostname without `connect_to`.

## Use a separate public address per server

1. In Cloudflare, give the server its own published hostname and protect it with a self-hosted Access application. Route each published hostname to the same origin, `http://rustguac:8080`. In the Tunnel route, set **HTTP Host Header** to that route’s public hostname so it reaches rustguac as the request host.
2. Set `RDP_TARGETS` in Coolify to a JSON array. Each entry maps one public hostname to one internal host or IP on port 3389. Set `access_aud` to the AUD tag of the Access application for that hostname.

```json
[
  {"public_host":"rdp-01.example.com","target_host":"windows-01.ad.example.com","access_aud":"AUD_FOR_RDP_01"},
  {"public_host":"rdp-02.example.com","target_host":"windows-02.ad.example.com","access_aud":"AUD_FOR_RDP_02"}
]
```

3. Redeploy rustguac. Visiting `https://rdp-02.example.com/` now opens the second server. An unconfigured hostname returns 404. Using an Access token issued solely for another server fails audience validation.

For an existing single-server setup, leaving `RDP_TARGETS` empty keeps `RDP_TARGET_HOST` and `CF_ACCESS_AUD` as the settings. All configured targets share the AD provisioning settings below. The AD group must grant RDP access on each target.

## Active Directory and RDP

- Mount a PEM containing the CA certificates for LDAPS. Set `AD_CA_CERT_HOST_PATH` to the host path readable by the rustguac container.
- Set `AD_LDAPS_URL`, `AD_BIND_DN`, `AD_BIND_PASSWORD`, `AD_USERS_OU`, `AD_RDP_GROUP_DN`, and `AD_DOMAIN`. Use a writable DC and its certificate hostname in `AD_LDAPS_URL`. Ensure both containers can resolve and reach their respective Windows endpoints. Rustguac connects to LDAPS on 636 and guacd connects to RDP on 3389.
- Delegate the service account read and user creation rights in the dedicated OU, write access to the attributes rustguac sets, the Reset Password right, and write access to `member` on the chosen RDP group. Grant that group access to the Session Host, including its effective **Allow log on through Remote Desktop Services** policy.
- Rustguac uses the Entra tenant and object IDs to identify managed AD users. The Windows logon name uses up to seven characters from the email login and a stable suffix. Reserve the OU for these accounts and preserve their CN and ownership marker in `description`. A person with a pre-existing Windows account gets a separate managed account on first access. Rustguac only resets the password for the managed account.
- Use the RDP server's certificate hostname and a certificate trusted by guacd. The explicit `RDP_IGNORE_CERT=true` override is available for troubleshooting. If the Session Host authenticates against a different DC, check password replication if the initial NLA login fails.

## OpenBao

The bundled OpenBao uses persistent integrated Raft storage on a private Docker network. Initialize it once and unseal it before serving users. Run administration commands from the OpenBao service terminal with `BAO_ADDR=http://127.0.0.1:8200`. Keep recovery material and the initial administrative token outside the application.

Enable a KV v2 mount named `secret` and AppRole auth if needed. Give a dedicated AppRole a policy limited to the RDP passwords. Read access lets the app reuse the same password when a user already has a desktop opening or running on another server.

```hcl
path "secret/data/rdp-users/*" {
  capabilities = ["create", "read", "update"]
}
```

Set `VAULT_ROLE_ID` and `VAULT_SECRET_ID` in Coolify using the AppRole credentials. Rustguac reuses its existing AppRole authentication and renewal. For a separate Vault/OpenBao service, set `VAULT_ADDR` and use its dedicated AppRole. Each successful password write stores the timestamp and password at `secret/data/rdp-users/<sAMAccountName>`. Configure a KV version retention limit on a dedicated mount if it should retain only the latest version.

## Pilot verification

- A user without the App Role should get a denial and cause no writes in AD or OpenBao.
- A user with the role should get a managed AD account and a working Windows session. A new launch after closing all of the user’s desktops should rotate the password. On the same server, overlapping launch requests reuse the pending session or report that the desktop is already open. With two configured hostnames, check that each opens its own target and that a JWT for one hostname is rejected on the other.
- A provisioning or OpenBao failure should prevent session creation. A subsequent launch retries the setup with a fresh password.
