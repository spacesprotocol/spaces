use std::{env};

use env_logger::Env;
use log::error;
use spaces_client::{
    config::{safe_exit},
};
use tokio::{
    sync::{broadcast},
};
use spaces_client::app::App;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let sigterm = tokio::signal::ctrl_c();

    let (shutdown, _) = broadcast::channel(1);
    let mut app = App::new(shutdown.clone());

    tokio::spawn(async move {
        sigterm.await.expect("could not listen for shutdown");
        let _ = shutdown.send(());
    });

    match app.run(env::args().collect()).await {
        Ok(_) => {}
        Err(e) => {
            error!("{}", e.to_string());
            safe_exit(1);
        }
    }
}
