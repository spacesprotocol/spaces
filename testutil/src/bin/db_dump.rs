use std::path::PathBuf;
use std::collections::HashMap;
use std::fs::OpenOptions;
use anyhow::Result;
use spaces_protocol::{SpaceOut, hasher::{SpaceKey, OutpointKey, BidKey}};
use serde_json;
use spacedb::{db::Database, fs::FileBackend, Configuration, Sha256Hasher};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} --type <spaces|ptrs> <db_path> [compare_db_path]", args[0]);
        eprintln!("\nDumps or compares spaces/ptrs databases");
        eprintln!("  <db_path>: Direct path to the database file");
        eprintln!("  [compare_db_path]: Optional second database to compare with");
        std::process::exit(1);
    }

    if args[1] != "--type" {
        eprintln!("Error: First argument must be --type");
        std::process::exit(1);
    }

    let db_type = &args[2];
    if db_type != "spaces" && db_type != "ptrs" {
        eprintln!("Error: type must be 'spaces' or 'ptrs'");
        std::process::exit(1);
    }

    let db_path = PathBuf::from(&args[3]);

    if args.len() == 5 {
        let compare_path = PathBuf::from(&args[4]);
        compare_databases(db_type, &db_path, &compare_path)?;
    } else {
        dump_database(db_type, &db_path)?;
    }

    Ok(())
}

fn open_db(path: PathBuf) -> Result<Database<Sha256Hasher>> {
    let file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(path)?;

    let config = Configuration::new().with_cache_size(1000000);
    Ok(Database::new(Box::new(FileBackend::new(file)?), config)?)
}

fn dump_database(db_type: &str, db_path: &PathBuf) -> Result<()> {
    println!("=== Database Dump: {} ===", db_path.display());
    println!("Type: {}\n", db_type);

    let db = open_db(db_path.clone())?;

    match db_type {
        "spaces" => dump_spaces(&db)?,
        "ptrs" => dump_ptrs(&db)?,
        _ => unreachable!(),
    }

    Ok(())
}

fn dump_spaces(db: &Database<Sha256Hasher>) -> Result<()> {
    // Get the latest snapshot
    let mut snap = db.begin_read()?;
    let root = snap.compute_root()?;
    let metadata = snap.metadata();

    println!("Root Hash: {}", hex::encode(root));
    println!("Metadata: {} bytes", metadata.len());
    if !metadata.is_empty() {
        println!("Metadata (hex): {}", hex::encode(metadata));
    }
    println!();

    // Count entries by type
    let mut space_keys = 0;
    let mut outpoint_keys = 0;
    let mut bid_keys = 0;
    let mut unknown = 0;

    for item in snap.iter() {
        let (key, _value) = item?;

        if SpaceKey::is_valid(&key) {
            space_keys += 1;
        } else if OutpointKey::is_valid(&key) {
            outpoint_keys += 1;
        } else if BidKey::is_valid(&key) {
            bid_keys += 1;
        } else {
            unknown += 1;
        }
    }

    println!("Space entries (name -> spaceout): {}", space_keys);
    println!("Outpoint entries (outpoint -> spaceout): {}", outpoint_keys);
    println!("Bid entries (bid -> space): {}", bid_keys);
    if unknown > 0 {
        println!("Unknown entries: {}", unknown);
    }

    Ok(())
}

fn dump_ptrs(db: &Database<Sha256Hasher>) -> Result<()> {
    // Get the latest snapshot
    let mut snap = db.begin_read()?;
    let root = snap.compute_root()?;
    let metadata = snap.metadata();

    println!("Root Hash: {}", hex::encode(root));
    println!("Metadata: {} bytes", metadata.len());
    if !metadata.is_empty() {
        println!("Metadata (hex): {}", hex::encode(metadata));
    }
    println!();

    // Count total entries
    let mut count = 0;
    for item in snap.iter() {
        let _ = item?;
        count += 1;
    }

    println!("Total PTR entries: {}", count);

    Ok(())
}

fn compare_databases(db_type: &str, db1_path: &PathBuf, db2_path: &PathBuf) -> Result<()> {
    println!("=== Comparing Databases ===");
    println!("Type: {}", db_type);
    println!("DB1: {}", db1_path.display());
    println!("DB2: {}", db2_path.display());
    println!();

    let db1 = open_db(db1_path.clone())?;
    let db2 = open_db(db2_path.clone())?;

    match db_type {
        "spaces" => compare_spaces(&db1, &db2)?,
        "ptrs" => compare_ptrs(&db1, &db2)?,
        _ => unreachable!(),
    }

    Ok(())
}

fn identify_key_type(key: &[u8; 32]) -> &'static str {
    if SpaceKey::is_valid(key) {
        "SpaceKey"
    } else if OutpointKey::is_valid(key) {
        "OutpointKey"
    } else if BidKey::is_valid(key) {
        "BidKey"
    } else {
        "Unknown"
    }
}

fn decode_value(key: &[u8; 32], value: &[u8]) -> Result<serde_json::Value> {
    if SpaceKey::is_valid(key) {
        // Value is a SpaceOut
        match borsh::from_slice::<SpaceOut>(value) {
            Ok(spaceout) => {
                return Ok(serde_json::to_value(&spaceout)?);
            }
            Err(e) => {
                eprintln!("Warning: Failed to decode SpaceOut: {}", e);
            }
        }
    } else if OutpointKey::is_valid(key) {
        // Value is ALSO a SpaceOut (OutpointKey is used to look up spaceout by outpoint)
        match borsh::from_slice::<SpaceOut>(value) {
            Ok(spaceout) => {
                return Ok(serde_json::to_value(&spaceout)?);
            }
            Err(e) => {
                eprintln!("Warning: Failed to decode SpaceOut for OutpointKey: {}", e);
            }
        }
    } else if BidKey::is_valid(key) {
        // Value is a Space
        match borsh::from_slice::<spaces_protocol::Space>(value) {
            Ok(space) => {
                return Ok(serde_json::to_value(&space)?);
            }
            Err(e) => {
                eprintln!("Warning: Failed to decode Space: {}", e);
            }
        }
    }

    // Fallback: just show hex
    Ok(serde_json::json!({
        "hex": hex::encode(value),
        "len": value.len()
    }))
}

fn compare_spaces(db1: &Database<Sha256Hasher>, db2: &Database<Sha256Hasher>) -> Result<()> {
    let mut snap1 = db1.begin_read()?;
    let mut snap2 = db2.begin_read()?;

    let root1 = snap1.compute_root()?;
    let root2 = snap2.compute_root()?;

    println!("Root 1: {}", hex::encode(root1));
    println!("Root 2: {}", hex::encode(root2));
    println!();

    // Collect all entries from both databases and sort by key
    let mut entries1: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    let mut entries2: Vec<([u8; 32], Vec<u8>)> = Vec::new();

    for item in snap1.iter() {
        let (key, value) = item?;
        entries1.push((key, value));
    }

    for item in snap2.iter() {
        let (key, value) = item?;
        entries2.push((key, value));
    }

    // Sort by key to ensure consistent comparison
    entries1.sort_by_key(|(k, _)| *k);
    entries2.sort_by_key(|(k, _)| *k);

    println!("DB1 entries: {}", entries1.len());
    println!("DB2 entries: {}", entries2.len());
    println!();

    // Check if datasets are identical (ignoring tree structure)
    if entries1 == entries2 {
        println!("✓ Datasets are identical!");
        println!("  Note: Root hashes differ due to different insertion order/tree structure");
        return Ok(());
    }

    println!("✗ Datasets differ!");
    println!();

    // Build lookup maps for efficient comparison
    let map1: HashMap<[u8; 32], &Vec<u8>> = entries1.iter().map(|(k, v)| (*k, v)).collect();
    let map2: HashMap<[u8; 32], &Vec<u8>> = entries2.iter().map(|(k, v)| (*k, v)).collect();

    // Find differences
    let mut only_in_1 = 0;
    let mut only_in_2 = 0;
    let mut different_values = 0;

    // Check entries only in DB1
    for (key, value1) in &entries1 {
        if !map2.contains_key(key) {
            println!("Entry only in DB1:");
            println!("  Key type: {}", identify_key_type(key));
            println!("  Key: {}", hex::encode(key));
            match decode_value(key, value1) {
                Ok(decoded) => println!("  Value: {}", serde_json::to_string_pretty(&decoded)?),
                Err(_) => println!("  Value (hex): {}", hex::encode(value1)),
            }
            println!();
            only_in_1 += 1;
        }
    }

    // Check entries in DB2 (only or different)
    for (key, value2) in &entries2 {
        if let Some(value1) = map1.get(key) {
            if value1 != &value2 {
                println!("Entry with different values:");
                println!("  Key type: {}", identify_key_type(key));
                println!("  Key: {}", hex::encode(key));

                println!("  DB1 value:");
                match decode_value(key, value1) {
                    Ok(decoded) => println!("    {}", serde_json::to_string_pretty(&decoded)?),
                    Err(_) => println!("    (hex): {}", hex::encode(value1)),
                }

                println!("  DB2 value:");
                match decode_value(key, value2) {
                    Ok(decoded) => println!("    {}", serde_json::to_string_pretty(&decoded)?),
                    Err(_) => println!("    (hex): {}", hex::encode(value2)),
                }
                println!();
                different_values += 1;
            }
        } else {
            println!("Entry only in DB2:");
            println!("  Key type: {}", identify_key_type(key));
            println!("  Key: {}", hex::encode(key));
            match decode_value(key, value2) {
                Ok(decoded) => println!("  Value: {}", serde_json::to_string_pretty(&decoded)?),
                Err(_) => println!("  Value (hex): {}", hex::encode(value2)),
            }
            println!();
            only_in_2 += 1;
        }
    }

    println!("Summary:");
    println!("  Entries only in DB1: {}", only_in_1);
    println!("  Entries only in DB2: {}", only_in_2);
    println!("  Entries with different values: {}", different_values);

    Ok(())
}

fn compare_ptrs(db1: &Database<Sha256Hasher>, db2: &Database<Sha256Hasher>) -> Result<()> {
    let mut snap1 = db1.begin_read()?;
    let mut snap2 = db2.begin_read()?;

    let root1 = snap1.compute_root()?;
    let root2 = snap2.compute_root()?;

    println!("Root 1: {}", hex::encode(root1));
    println!("Root 2: {}", hex::encode(root2));
    println!();

    // Collect all entries from both databases and sort by key
    let mut entries1: Vec<([u8; 32], Vec<u8>)> = Vec::new();
    let mut entries2: Vec<([u8; 32], Vec<u8>)> = Vec::new();

    for item in snap1.iter() {
        let (key, value) = item?;
        entries1.push((key, value));
    }

    for item in snap2.iter() {
        let (key, value) = item?;
        entries2.push((key, value));
    }

    // Sort by key to ensure consistent comparison
    entries1.sort_by_key(|(k, _)| *k);
    entries2.sort_by_key(|(k, _)| *k);

    println!("DB1 entries: {}", entries1.len());
    println!("DB2 entries: {}", entries2.len());
    println!();

    // Check if datasets are identical (ignoring tree structure)
    if entries1 == entries2 {
        println!("✓ Datasets are identical!");
        println!("  Note: Root hashes differ due to different insertion order/tree structure");
        return Ok(());
    }

    println!("✗ Datasets differ!");
    println!();

    // Build lookup maps for efficient comparison
    let map1: HashMap<[u8; 32], &Vec<u8>> = entries1.iter().map(|(k, v)| (*k, v)).collect();
    let map2: HashMap<[u8; 32], &Vec<u8>> = entries2.iter().map(|(k, v)| (*k, v)).collect();

    // Find differences
    let mut only_in_1 = 0;
    let mut only_in_2 = 0;
    let mut different_values = 0;

    for (key, value1) in &entries1 {
        if !map2.contains_key(key) {
            println!("Entry only in DB1:");
            println!("  Key: {}", hex::encode(key));
            println!("  Value (hex): {}", hex::encode(value1));
            println!();
            only_in_1 += 1;
        }
    }

    for (key, value2) in &entries2 {
        if let Some(value1) = map1.get(key) {
            if value1 != &value2 {
                println!("Entry with different values:");
                println!("  Key: {}", hex::encode(key));
                println!("  DB1 value (hex): {}", hex::encode(value1));
                println!("  DB2 value (hex): {}", hex::encode(value2));
                println!();
                different_values += 1;
            }
        } else {
            println!("Entry only in DB2:");
            println!("  Key: {}", hex::encode(key));
            println!("  Value (hex): {}", hex::encode(value2));
            println!();
            only_in_2 += 1;
        }
    }

    println!("Summary:");
    println!("  Entries only in DB1: {}", only_in_1);
    println!("  Entries only in DB2: {}", only_in_2);
    println!("  Entries with different values: {}", different_values);

    Ok(())
}
