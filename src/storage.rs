use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::model::CapturedExchange;

#[derive(Clone, Debug)]
pub struct BodyStore {
    root: PathBuf,
}

impl BodyStore {
    pub fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn put(&self, body: &[u8]) -> Result<String> {
        let key = hex::encode(Sha256::digest(body));
        let folder = self.root.join(&key[0..2]);
        let path = folder.join(&key);
        if !path.exists() {
            fs::create_dir_all(folder)?;
            let temporary = path.with_extension("tmp");
            fs::write(&temporary, body)?;
            fs::rename(temporary, path)?;
        }
        Ok(key)
    }

    pub fn get(&self, key: &str) -> Result<Vec<u8>> {
        Ok(fs::read(self.root.join(&key[0..2]).join(key))?)
    }

    pub fn delete(&self, key: &str) -> Result<()> {
        let path = self.root.join(&key[0..2]).join(key);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SessionRepository {
    database_path: PathBuf,
}

impl SessionRepository {
    pub fn new(database_path: PathBuf) -> Self {
        Self { database_path }
    }

    pub fn initialize(&self) -> Result<()> {
        if let Some(parent) = self.database_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let connection = self.connect()?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS exchanges (
                exchange_id TEXT PRIMARY KEY,
                sequence INTEGER NOT NULL,
                host TEXT NOT NULL,
                method TEXT NOT NULL,
                status_code INTEGER,
                captured_at TEXT NOT NULL,
                pinned INTEGER NOT NULL,
                metadata_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_exchanges_sequence ON exchanges(sequence);",
        )?;
        Ok(())
    }

    pub fn add_exchange(&self, exchange: &CapturedExchange) -> Result<()> {
        let json = serde_json::to_string(exchange)?;
        let response_status = exchange.response.as_ref().map(|response| response.status);
        self.connect()?.execute(
            "INSERT OR REPLACE INTO exchanges (
                exchange_id, sequence, host, method, status_code, captured_at, pinned, metadata_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                exchange.id.to_string(),
                exchange.sequence as i64,
                exchange.request.host,
                exchange.request.method,
                response_status,
                exchange.request.timestamp.to_rfc3339(),
                exchange.pinned,
                json,
            ],
        )?;
        Ok(())
    }

    pub fn get_exchange(&self, id: Uuid) -> Result<Option<CapturedExchange>> {
        let json: Option<String> = self
            .connect()?
            .query_row(
                "SELECT metadata_json FROM exchanges WHERE exchange_id = ?1",
                [id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        json.map(|value| serde_json::from_str(&value).context("stored exchange JSON is invalid"))
            .transpose()
    }

    pub fn list_exchanges(&self, limit: usize, offset: usize) -> Result<Vec<CapturedExchange>> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT metadata_json FROM exchanges ORDER BY sequence DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = statement.query_map(params![limit as i64, offset as i64], |row| {
            row.get::<_, String>(0)
        })?;
        let mut exchanges = Vec::new();
        for row in rows {
            exchanges.push(serde_json::from_str(&row?).context("stored exchange JSON is invalid")?);
        }
        Ok(exchanges)
    }

    pub fn delete_exchange(&self, id: Uuid) -> Result<()> {
        self.connect()?.execute(
            "DELETE FROM exchanges WHERE exchange_id = ?1",
            [id.to_string()],
        )?;
        Ok(())
    }

    fn connect(&self) -> Result<Connection> {
        Ok(Connection::open(&self.database_path)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_bodies_by_content_hash() {
        let temp = tempfile::tempdir().unwrap();
        let store = BodyStore::new(temp.path().to_path_buf()).unwrap();
        let key = store.put(b"hello").unwrap();
        assert_eq!(store.get(&key).unwrap(), b"hello");
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn session_repository_round_trips_exchanges() {
        use crate::model::{CapturedRequest, Header};
        use chrono::Utc;

        let temp = tempfile::tempdir().unwrap();
        let repository = SessionRepository::new(temp.path().join("sessions.db"));
        repository.initialize().unwrap();
        let exchange = CapturedExchange {
            id: Uuid::new_v4(),
            sequence: 7,
            request: CapturedRequest {
                method: "GET".into(),
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                path: "/api".into(),
                version: "HTTP/2.0".into(),
                headers: vec![Header {
                    name: "Authorization".into(),
                    value: "Bearer test".into(),
                }],
                body: Vec::new(),
                timestamp: Utc::now(),
                client_addr: "127.0.0.1:50000".into(),
                process: String::new(),
                pid: None,
            },
            response: None,
            rule_matched: None,
            error: None,
            synthetic: false,
            pinned: false,
            notes: String::new(),
        };
        repository.add_exchange(&exchange).unwrap();
        let loaded = repository.get_exchange(exchange.id).unwrap().unwrap();
        assert_eq!(loaded.request.host, "example.test");
        assert_eq!(repository.list_exchanges(10, 0).unwrap().len(), 1);
        repository.delete_exchange(exchange.id).unwrap();
        assert!(repository.get_exchange(exchange.id).unwrap().is_none());
    }
}
