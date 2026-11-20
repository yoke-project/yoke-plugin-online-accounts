# The watch

| | |
| --- | --- |
| **Feature** | this Plugin against what Yoke last published |
| **Planning item** | yoke-project/yoke-plugin-online-accounts#1 |

## yoke-plugin-online-accounts:the-watch.01 — built, packaged and installed by the newest release of Yoke, the Plugin runs under its Core holding the secret it rewrites and answers its accounts

| Field | Value |
| --- | --- |
| **Cites** | specs/95.40 · specs/80.56 |
| **Level** | L3 |
| **Method** | check |
| **Not applicable in** | — |
| **Label** | blocking |
| **Precondition** | the newest published programs of Yoke; no provider's client and no account |
| **Action** | build the Plugin, take it into `try/`, package and install it as an instance, set the secrets `clients` and `tokens` to `{}`, start it, grant `oauth.accounts` and ask it |
| **Expected** | the instance comes up; the question is answered with an empty list of accounts |
