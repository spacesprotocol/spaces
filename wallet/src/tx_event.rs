use std::{fmt, fmt::Display, str::FromStr};

use bdk_wallet::{
    chain, rusqlite,
    rusqlite::{
        types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef},
        ToSql,
    },
};
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, Txid};
use serde::{Deserialize, Serialize};
use protocol::{Covenant, FullSpaceOut};
use crate::rusqlite_impl::{migrate_schema, Impl};
use crate::SpacesWallet;

#[derive(Clone, Debug)]
pub struct TxRecord {
    pub tx: Transaction,
    pub events: Vec<TxEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxEvent {
    #[serde(rename = "type")]
    pub kind: TxEventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreign_input: Option<OutPoint>,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BidEventDetails {
    pub bid_current: Amount,
    pub bid_previous: Amount,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferEventDetails {
    pub to: ScriptBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BidoutEventDetails {
    pub count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendEventDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_space: Option<String>,
    pub resolved_address: ScriptBuf,
    pub amount: Amount,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenEventDetails {
    pub bid_initial: Amount,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommitEventDetails {
    pub reveal_script_pubkey: protocol::Bytes,
    /// [SpaceScriptSigningInfo] in raw format
    pub reveal_signing_info: protocol::Bytes,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecuteEventDetails {
    pub space_script_input_index: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxEventKind {
    Commit,
    Bidout,
    Open,
    Script,
    Bid,
    Register,
    Transfer,
    Send,
    FeeBump,
}

impl TxEvent {
    pub const TX_EVENTS_TABLE_NAME: &'static str = "spaces_tx_events";
    pub const TX_EVENTS_SCHEMA_NAME: &'static str = "spaces_tx_events_schema";

    pub fn init_sqlite_tables(db_tx: &chain::rusqlite::Transaction) -> chain::rusqlite::Result<()> {
        let schema_v0: &[&str] = &[&format!(
            "CREATE TABLE {} ( \
                id INTEGER PRIMARY KEY AUTOINCREMENT, \
                txid TEXT NOT NULL, \
                type TEXT NOT NULL, \
                space TEXT, \
                foreign_input TEXT, \
                details TEXT \
            ) STRICT;",
            Self::TX_EVENTS_TABLE_NAME,
        )];

        migrate_schema(db_tx, Self::TX_EVENTS_SCHEMA_NAME, &[schema_v0])
    }

    pub fn all(db_tx: &rusqlite::Transaction, txid: Txid) -> rusqlite::Result<Vec<Self>> {
        let stmt = db_tx.prepare(&format!(
            "SELECT type, space, foreign_input, details
         FROM {} WHERE txid = ?1",
            Self::TX_EVENTS_TABLE_NAME,
        ))?;
        Self::from_sqlite_statement(stmt, [Impl(txid)])
    }

    pub fn bids(db_tx: &rusqlite::Transaction, space: String) -> rusqlite::Result<Vec<Self>> {
        let stmt = db_tx.prepare(&format!(
            "SELECT type, space, foreign_input, details
         FROM {} WHERE type = 'bid' AND space = ?1",
            Self::TX_EVENTS_TABLE_NAME,
        ))?;
        Self::from_sqlite_statement(stmt, [space])
    }

    pub fn filter_bids(
        db_tx: &rusqlite::Transaction,
        txids: Vec<Txid>,
    ) -> rusqlite::Result<Vec<(Txid, OutPoint)>> {
        if txids.is_empty() {
            return Ok(Vec::new());
        }
        let query_placeholders = txids.iter().map(|_| "?").collect::<Vec<_>>().join(",");

        let mut stmt = db_tx.prepare(&format!(
            "SELECT txid, foreign_input
         FROM {}
         WHERE foreign_input IS NOT NULL AND type = 'bid' AND txid IN ({})",
            Self::TX_EVENTS_TABLE_NAME,
            query_placeholders
        ))?;

        let rows = stmt.query_map(
            rusqlite::params_from_iter(txids.into_iter().map(|t| Impl(t))),
            |row| {
                let txid: Impl<Txid> = row.get(0)?;
                let foreign_input: Option<Impl<OutPoint>> = row.get(1)?;
                Ok((txid, foreign_input.map(|x| x.0).unwrap()))
            },
        )?;
        let mut results = Vec::new();
        for row in rows {
            if let Ok((txid, outpoint)) = row {
                results.push((txid.0, outpoint));
            }
        }
        Ok(results)
    }

    pub fn all_bid_txs(db_tx: &rusqlite::Transaction, txid: Txid) -> rusqlite::Result<Option<Self>> {
        let stmt = db_tx.prepare(&format!(
            "SELECT type, space, foreign_input, details
         FROM {} WHERE type = 'bid' AND txid = ?1",
            Self::TX_EVENTS_TABLE_NAME,
        ))?;
        let results: Vec<Self> = Self::from_sqlite_statement(stmt, [Impl(txid)])?;
        Ok(results.get(0).cloned())
    }

    pub fn spaces(db_tx: &rusqlite::Transaction) -> rusqlite::Result<Vec<String>> {
        let query = format!(
            "SELECT DISTINCT space
         FROM {}
         WHERE type = 'bid' AND space IS NOT NULL",
            Self::TX_EVENTS_TABLE_NAME,
        );

        let mut stmt = db_tx.prepare(&query)?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

        let mut spaces = Vec::new();
        for space in rows {
            spaces.push(space?);
        }
        Ok(spaces)
    }

    fn from_sqlite_statement<P: rusqlite::Params>(
        mut stmt: rusqlite::Statement,
        params: P,
    ) -> rusqlite::Result<Vec<Self>> {
        let row_iter = stmt.query_map(params, |row| {
            Ok((
                row.get::<_, TxEventKind>("type")?,
                row.get::<_, Option<String>>("space")?,
                row.get::<_, Option<Impl<OutPoint>>>("foreign_input")?,
                row.get::<_, Option<Impl<serde_json::Value>>>("details")?,
            ))
        })?;

        let mut events = Vec::new();
        for row in row_iter {
            let (event_type, space, foreign_input, details) = row?;
            events.push(TxEvent {
                kind: event_type,
                space,
                foreign_input: foreign_input.map(|x| x.0),
                details: details.map(|x| x.0),
            })
        }

        Ok(events)
    }

    pub fn insert(
        db_tx: &rusqlite::Transaction,
        txid: Txid,
        kind: TxEventKind,
        space: Option<String>,
        foreign_input: Option<OutPoint>,
        details: Option<serde_json::Value>,
    ) -> rusqlite::Result<usize> {
        let query = format!(
            "INSERT INTO {} (txid, type, space, foreign_input, details)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            Self::TX_EVENTS_TABLE_NAME,
        );

        db_tx.execute(
            &query,
            rusqlite::params![
                txid.to_string(),
                kind,
                space,
                foreign_input.map(|b| b.to_string()),
                details.map(|d| d.to_string())
            ],
        )?;

        Ok(db_tx.last_insert_rowid() as usize)
    }
}


impl TxRecord {
    pub fn new(tx: Transaction) -> Self {
        Self {
            events: Vec::new(),
            tx,
        }
    }

    pub fn new_with_events(tx: Transaction, events: Vec<TxEvent>) -> Self {
        Self {
            events,
            tx,
        }
    }

    pub fn add_fee_bump(&mut self) {
        self.events.push(TxEvent {
            kind: TxEventKind::FeeBump,
            space: None,
            foreign_input: None,
            details: None,
        });
    }

    pub fn add_transfer(&mut self, space: String, to: ScriptBuf) {
        self.events.push(TxEvent {
            kind: TxEventKind::Transfer,
            space: Some(space),
            foreign_input: None,
            details: Some(serde_json::to_value(TransferEventDetails { to }).expect("json value")),
        });
    }

    pub fn add_bidout(&mut self, count: usize) {
        self.events.push(TxEvent {
            kind: TxEventKind::Bidout,
            space: None,
            foreign_input: None,
            details: Some(serde_json::to_value(BidoutEventDetails { count }).expect("json value")),
        });
    }

    pub fn add_send(
        &mut self,
        amount: Amount,
        to_space: Option<String>,
        resolved_address: ScriptBuf,
    ) {
        self.events.push(TxEvent {
            kind: TxEventKind::Send,
            space: None,
            foreign_input: None,
            details: Some(
                serde_json::to_value(SendEventDetails {
                    to_space,
                    resolved_address,
                    amount,
                })
                    .expect("json value"),
            ),
        });
    }

    // Should be added for every space affected by this commitment
    pub fn add_commitment(
        &mut self,
        space: String,
        reveal_address: ScriptBuf,
        signing_info: Vec<u8>,
    ) {
        self.events.push(TxEvent {
            kind: TxEventKind::Commit,
            space: Some(space),
            foreign_input: None,
            details: Some(
                serde_json::to_value(CommitEventDetails {
                    reveal_script_pubkey: protocol::Bytes::new(reveal_address.to_bytes()),
                    reveal_signing_info: protocol::Bytes::new(signing_info),
                })
                    .expect("json value"),
            ),
        });
    }

    pub fn add_open(&mut self, space: String, initial_bid: Amount) {
        self.events.push(TxEvent {
            kind: TxEventKind::Open,
            space: Some(space),
            foreign_input: None,
            details: Some(
                serde_json::to_value(OpenEventDetails {
                    bid_initial: initial_bid,
                })
                    .expect("json value"),
            ),
        });
    }

    // Should be added for each space affected
    pub fn add_execute(&mut self, space: String, reveal_input_index: usize) {
        self.events.push(TxEvent {
            kind: TxEventKind::Script,
            space: Some(space),
            foreign_input: None,
            details: Some(
                serde_json::to_value(ExecuteEventDetails {
                    space_script_input_index: reveal_input_index,
                })
                    .expect("json value"),
            ),
        });
    }

    pub fn add_bid(&mut self, wallet: &mut SpacesWallet, previous: &FullSpaceOut, amount: Amount) {
        let space = previous.spaceout.space.as_ref().expect("space not found");
        let previous_bid = match space.covenant {
            Covenant::Bid { total_burned, .. } => total_burned,
            _ => panic!("expected a bid"),
        };
        self.events.push(TxEvent {
            kind: TxEventKind::Bid,
            space: Some(space.name.to_string()),
            foreign_input: match wallet.is_mine(previous.spaceout.script_pubkey.clone()) {
                false => Some(previous.outpoint()),
                true => None
            },
            details: Some(
                serde_json::to_value(BidEventDetails {
                    bid_current: amount,
                    bid_previous: previous_bid,
                })
                    .expect("json value"),
            ),
        });
    }
}


#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, Txid};
    use serde_json::json;
    use tempfile::tempdir;

    use crate::{tx_event::TxEventKind, *};

    #[test]
    fn test_tx_event() -> anyhow::Result<()> {
        // Create a temporary directory
        let tmp_dir = tempdir()?;
        let db_path = tmp_dir.path().join("test.db");

        // Initialize SQLite connection
        let mut conn = Connection::open(&db_path)?;
        let tx = conn.transaction()?;

        // Initialize the table
        TxEvent::init_sqlite_tables(&tx)?;

        // Insert a sample transaction event
        let txid = Txid::all_zeros();
        let kind = TxEventKind::Bid;
        let space = Some("test_space".to_string());
        let details = Some(json!({"amount": 1000, "currency": "USD"}));

        TxEvent::insert(&tx, txid, kind, space.clone(), None, details.clone())?;

        // Commit the transaction
        tx.commit()?;

        // Re-open the connection to verify the insertion
        let mut conn = Connection::open(&db_path)?;
        let tx = conn.transaction()?;

        // Query the inserted event
        let inserted_events = TxEvent::all(&tx, txid)?;

        assert_eq!(inserted_events.len(), 1);
        let event = &inserted_events[0];
        assert_eq!(event.space, space);
        assert_eq!(event.details, details);

        let mut conn = Connection::open(&db_path)?;
        let tx = conn.transaction()?;

        let spaces = TxEvent::spaces(&tx)?;
        assert_eq!(spaces.len(), 1);
        assert_eq!(spaces[0], "test_space");

        let bids = TxEvent::bids(&tx, "test_space".to_string())?;
        assert_eq!(bids.len(), 1);
        assert!(matches!(bids[0].kind, TxEventKind::Bid));

        Ok(())
    }
}

impl Display for TxEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TxEventKind::Commit => "commit",
            TxEventKind::Bidout => "bidout",
            TxEventKind::Open => "open",
            TxEventKind::Bid => "bid",
            TxEventKind::Register => "register",
            TxEventKind::Transfer => "transfer",
            TxEventKind::Send => "send",
            TxEventKind::Script => "script",
            TxEventKind::FeeBump => "fee-bump"
        })
    }
}

impl FromStr for TxEventKind {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "commit" => Ok(TxEventKind::Commit),
            "bidout" => Ok(TxEventKind::Bidout),
            "open" => Ok(TxEventKind::Open),
            "bid" => Ok(TxEventKind::Bid),
            "register" => Ok(TxEventKind::Register),
            "transfer" => Ok(TxEventKind::Transfer),
            "send" => Ok(TxEventKind::Send),
            "script" => Ok(TxEventKind::Script),
            "fee-bump" => Ok(TxEventKind::FeeBump),
            _ => Err("invalid event kind"),
        }
    }
}

impl FromSql for TxEventKind {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        value
            .as_str()
            .map_err(|_| FromSqlError::InvalidType)?
            .parse()
            .map_err(|_| FromSqlError::InvalidType)
    }
}

impl ToSql for TxEventKind {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.to_string()))
    }
}
