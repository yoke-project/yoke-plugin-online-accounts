# Trying online-accounts

This directory is an application project that uses the Plugin in `..`: `yoke-compose init` made it and
`add plugin .. --yes` took the Plugin into it. Nothing here is the Plugin, and taking the Plugin into
another application never takes this directory.

| Path | What it is |
| --- | --- |
| `yoke.yaml` | the application: the unit `online-accounts`, given its two secrets, and the channel `panel`, a local socket for one client |
| `follow/` | an interface client: it asks every question, follows every stream and every event of the unit, and prints each as one line |
| `run.sh` | packages the application, installs it as the instance `oa` in a world of its own under `.world/`, grants what the Plugin declares, and follows the unit |

A unit's secrets are an installed instance's, so the application runs as one rather than as a run of a
directory: the world under `.world/` keeps it, and an account signed in stays signed in from one run to the
next. `--fresh` forgets it.

The programs of Yoke 0.17.0 or later are installed from the module proxy:

```sh
for p in yoke yoke-compose yoke-core yoke-guardian yoke-auth; do
  go install "github.com/yoke-project/yoke/cmd/$p@latest"
done
```

The clients are the deployment's: register a public client with Microsoft Entra ID that allows the device
code flow, and a desktop client with Google, and write them in a file as the Plugin's README shows.

```sh
./run.sh --clients ~/clients.json   # the first time; the clients are kept in the world
./run.sh                            # one line per answer, frame and event, until interrupted
./run.sh --seconds 10
```

Then sign in from another terminal, with the line `run.sh` prints: the stream shows the page and the code,
and once the person has finished it shows the account. Ask for a token the same way:

    yoke unit command online-accounts oauth.login --input - --instance oa <<< '{"provider":"microsoft","scopes":["Calendars.Read"]}'
    yoke unit ask online-accounts oauth.token --input - --instance oa <<< '{"account":"microsoft:ada@example.org"}'
