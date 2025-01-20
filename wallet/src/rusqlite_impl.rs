use std::str::FromStr;

// Simple schema migration adapted from bdk to include
// additional metadata stored alongside bdk's tables
// https://github.com/bitcoindevkit/bdk/blob/bcff89d51d0e1d91058e4430eda8cc57fb7f0f08/crates/chain/src/rusqlite_impl.rs#L55
use bdk_wallet::rusqlite;
use bdk_wallet::rusqlite::{
    named_params,
    types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef},
    OptionalExtension, ToSql, Transaction,
};

use crate::*;

/// Table name for schemas.
pub const SCHEMAS_TABLE_NAME: &str = "spaces_schemas";
pub struct Impl<T>(pub T);

/// Initialize the schema table.
fn init_schemas_table(db_tx: &Transaction) -> rusqlite::Result<()> {
    let sql = format!("CREATE TABLE IF NOT EXISTS {}( name TEXT PRIMARY KEY NOT NULL, version INTEGER NOT NULL ) STRICT", SCHEMAS_TABLE_NAME);
    db_tx.execute(&sql, ())?;
    Ok(())
}

/// Get schema version of `schema_name`.
fn schema_version(db_tx: &Transaction, schema_name: &str) -> rusqlite::Result<Option<u32>> {
    let sql = format!(
        "SELECT version FROM {} WHERE name=:name",
        SCHEMAS_TABLE_NAME
    );
    db_tx
        .query_row(&sql, named_params! { ":name": schema_name }, |row| {
            row.get::<_, u32>("version")
        })
        .optional()
}

/// Set the `schema_version` of `schema_name`.
fn set_schema_version(
    db_tx: &Transaction,
    schema_name: &str,
    schema_version: u32,
) -> rusqlite::Result<()> {
    let sql = format!(
        "REPLACE INTO {}(name, version) VALUES(:name, :version)",
        SCHEMAS_TABLE_NAME,
    );
    db_tx.execute(
        &sql,
        named_params! { ":name": schema_name, ":version": schema_version },
    )?;
    Ok(())
}

/// Runs logic that initializes/migrates the table schemas.
pub fn migrate_schema(
    db_tx: &Transaction,
    schema_name: &str,
    versioned_scripts: &[&[&str]],
) -> rusqlite::Result<()> {
    init_schemas_table(db_tx)?;
    let current_version = schema_version(db_tx, schema_name)?;
    let exec_from = current_version.map_or(0_usize, |v| v as usize + 1);
    let scripts_to_exec = versioned_scripts.iter().enumerate().skip(exec_from);
    for (version, &script) in scripts_to_exec {
        set_schema_version(db_tx, schema_name, version as u32)?;
        for statement in script {
            db_tx.execute(statement, ())?;
        }
    }
    Ok(())
}

impl FromSql for Impl<bitcoin::OutPoint> {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        bitcoin::OutPoint::from_str(value.as_str()?)
            .map(Self)
            .map_err(from_sql_error)
    }
}

impl ToSql for Impl<bitcoin::OutPoint> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(self.0.to_string().into())
    }
}

impl FromSql for Impl<Txid> {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Txid::from_str(value.as_str()?)
            .map(Self)
            .map_err(from_sql_error)
    }
}

impl ToSql for Impl<Txid> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(self.0.to_string().into())
    }
}

impl FromSql for Impl<serde_json::Value> {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        serde_json::Value::from_str(value.as_str()?)
            .map(Self)
            .map_err(from_sql_error)
    }
}

impl ToSql for Impl<serde_json::Value> {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(self.0.to_string().into())
    }
}

fn from_sql_error<E: std::error::Error + Send + Sync + 'static>(err: E) -> FromSqlError {
    FromSqlError::Other(Box::new(err))
}
