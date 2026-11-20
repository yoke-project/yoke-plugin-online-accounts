//! online-accounts: accounts held, signed in and renewed, as a Yoke Plugin unit.

use std::sync::Arc;
use std::time::Duration;

use online_accounts::accounts::Tokens;
use online_accounts::identity::{self, Network};
use online_accounts::plugin::{carry, declaration, handle, Online, Parts, Settings, PLUGIN};
use yoke_sdk::plugin::{start, Event};

/// How often the unit looks for an access token to renew.
const LOOK_EVERY: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() {
    // `online-accounts --manifest` prints the Manifest the declaration generates, which the bundle carries.
    if std::env::args().nth(1).as_deref() == Some("--manifest") {
        print!("{}", declaration().manifest());
        return;
    }
    let settings = match Settings::parse(std::env::args().skip(1)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("online-accounts: {e}");
            std::process::exit(2);
        }
    };
    // The clients are the deployment's: one it cannot read leaves every sign-in refused, and the unit says so.
    let (clients, clients_said) = match std::fs::read_to_string(&settings.clients)
        .map_err(|e| format!("the secret clients cannot be read: {e}"))
        .and_then(|text| identity::clients(&text))
    {
        Ok(c) => (c, None),
        Err(why) => (Default::default(), Some(why)),
    };
    let unit = match start(&declaration()).await {
        Ok(unit) => Arc::new(unit),
        Err(err) => {
            eprintln!("online-accounts: {err}");
            std::process::exit(1);
        }
    };
    let (happened_tx, mut happened) = tokio::sync::mpsc::unbounded_channel();
    let parts = Parts {
        http: Arc::new(Network::new()),
        providers: vec![identity::microsoft(&settings.tenant), identity::google()],
        clients,
        tokens: Tokens::at(&settings.tokens),
        give: settings.give,
        renew_before: settings.renew_before,
        login_within: settings.login_within,
        poll_wait: |d| d,
    };
    let configured: Vec<String> = parts.clients.keys().cloned().collect();
    let (online, read) = Online::new(parts, happened_tx);
    let (grade, line) = match (&read, &clients_said) {
        (Err(why), _) => (50, why.clone()),
        (_, Some(why)) => (50, why.clone()),
        (Ok(n), None) if configured.is_empty() => (
            50,
            format!("{n} accounts held, and the clients name no provider"),
        ),
        (Ok(n), None) => (
            0,
            format!("{n} accounts held; sign-in with {}", configured.join(", ")),
        ),
    };
    if let Err(err) = unit.health(grade, &line).await {
        eprintln!("{PLUGIN}: {err}");
    }
    // The access tokens renewed before they run out, from the start: a grant the provider no longer honours
    // is found before anyone asks.
    let renewing = online.clone();
    tokio::spawn(async move {
        loop {
            renewing.renew_due().await;
            tokio::time::sleep(LOOK_EVERY).await;
        }
    });
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("online-accounts listens for SIGTERM");
    loop {
        tokio::select! {
            event = unit.next() => match event {
                None | Some(Event::Ended(_)) => return,
                Some(Event::Activated(a)) => {
                    if let Err(err) = online.activated(unit.as_ref(), &a.stream).await {
                        eprintln!("online-accounts: {err}");
                    }
                }
                Some(Event::Stopped { stream }) => online.stopped(&stream),
                Some(event) => {
                    let (unit, online) = (unit.clone(), online.clone());
                    tokio::spawn(async move {
                        if let Err(err) = handle(unit.as_ref(), &event, &online).await {
                            eprintln!("online-accounts: {err}");
                        }
                    });
                }
            },
            Some(h) = happened.recv() => {
                if let Err(err) = carry(unit.as_ref(), &online, h).await {
                    eprintln!("online-accounts: {err}");
                }
            },
            _ = term.recv() => {
                let _ = unit.close().await;
                while let Some(event) = unit.next().await {
                    if matches!(event, Event::Ended(_)) {
                        break;
                    }
                }
                return;
            }
        }
    }
}
