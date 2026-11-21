# online-accounts

A Yoke Plugin that holds online accounts: it signs a person in with Microsoft or Google, keeps each
account's refresh token, renews access tokens before they run out, and gives an access token to whoever
asks and is given that account. Another unit uses it through a `unit:` need — `calendar` reads Microsoft
Graph and Google Calendar with the tokens it asks for, and holds no OAuth code of its own.

| | |
| --- | --- |
| questions | `oauth.accounts` `{}` (the accounts the asker is given, each with where it stands), `oauth.token` `{account, scopes?}` (an access token, renewed first where it runs out within a minute) |
| commands | `oauth.login` `{provider, scopes?}`, `oauth.logout` `{account}` |
| streams | `oauth.status`: every account and where it stands, and every sign-in in progress with its page and its code, at every change — never a token |
| occurrences | `oauth.signed_in` (10; 30 when a scope asked was not granted), `oauth.login.failed` (30), `oauth.sign_in_again` (40) |
| needs | `secret:clients`, `secret:tokens` — the second one rewritten by the unit itself |

Every payload is JSON and states `schema`. An account's identity is `<provider>:<username>`, the username
being who the provider says signed in. An account stands `valid`, `expiring` or `sign_in_again`.

**Signing in.** `oauth.login` starts a sign-in and is acknowledged with what the person must do; the stream
shows it until it ends, and an occurrence says how it ended. A provider may grant less than was asked —
Google lets the person untick a scope: the account keeps what was granted, and `oauth.signed_in` names what
was not in `withheld` and in its line, at severity 30.

| Provider | How | What the person does |
| --- | --- | --- |
| `microsoft` | device code | opens the page shown, on any device, and enters the code shown |
| `google` | authorization code with PKCE, redirected to `127.0.0.1` | opens the page shown in a browser **on this machine** |

Every sign-in also asks who the person is and for a token that renews (`openid`, `email`, and for Microsoft
`profile` and `offline_access`). Signing in again with an account already held replaces its grant.

**The clients are the deployment's.** The project registers no client of its own with any provider: whoever
deploys registers one with Microsoft Entra ID (a public client, device code allowed) and one with Google (a
desktop client), and supplies them as the secret `clients`:

```json
{
  "microsoft": { "client_id": "…" },
  "google": { "client_id": "….apps.googleusercontent.com", "client_secret": "…" }
}
```

A provider the secret does not name is refused `provider.unconfigured`. Google gives a desktop client a
secret that a desktop program cannot keep, and still asks for it.

**The refresh tokens rest in the secret `tokens`**, which the Manifest declares the unit rewrites: the unit
replaces it at every sign-in, every logout and every rotation, and is not restarted for its own write; a copy
of the instance carries none of it. It is supplied once as `{}`, before anyone signs in. A value this Plugin
did not write is never overwritten: the unit says so in its health and refuses to sign in. Access tokens
are held in memory alone.

**Who is given what** is the unit's arguments' to say, by who the Core says asked — `unit:<unit>`,
`channel:<name>`, `operator:<person>`:

    --give unit:calendar=microsoft:*,google:*   --give channel:panel=*

An account is named by its identity, by `<provider>:*`, or `*`; an asker by its name or `*`. With no
`--give` at all every asker is given every account: a desktop of one person, whose units are that person's.
An account the asker is not given is answered `not_found`, as one that does not exist. The stream carries
every account and is not scoped: it carries no token. A token asked with a scope the account was not
granted is refused `scope.missing`.

| Argument | |
| --- | --- |
| `--clients ${bind.clients}` | the deployment's clients |
| `--tokens ${bind.tokens}` | the accounts, rewritten by the unit |
| `--give <asker>=<accounts>` | repeated; none gives everything to everyone |
| `--tenant <tenant>` | Microsoft's tenant: `common` (the default), `organizations`, `consumers` or a tenant's identifier |
| `--renew-before-s N` | how long before it runs out an access token is renewed on the unit's own (300) |
| `--login-within-s N` | how long a browser sign-in waits for the person (600) |

A grant the provider no longer honours — revoked, expired, a password changed — marks the account
`sign_in_again` and is said once; it is not tried again until the person signs in again.

Not yet: other providers, and revoking a token at the provider on logout.

**It needs Yoke 0.17.0**, the release in which a unit rewrites its own secret and is told who asked; until
that release is published the Plugin builds on the Rust library at the commit that carries both.

Take it into an application with `yoke-compose add plugin https://github.com/yoke-project/yoke-plugin-online-accounts@<tag>`,
give its unit `--clients ${bind.clients} --tokens ${bind.tokens}`, and set both secrets on the instance. Build
it with `yoke-compose build`, and try it from `try/`.

Licensed under the Apache License 2.0.
