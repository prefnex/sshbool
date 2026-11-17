//! Remote database clients (psql / mysql / redis-cli / mongosh / sqlite3 over SSH).

use infrastructure::{audit, AppState};
use serde_json::{json, Value};
use std::sync::Arc;
use tauri::State;
use uuid::Uuid;

use crate::commands::common::db;
use crate::error::AppError;

// ── Database clients (remote CLI over SSH) ───────────────────────────

fn shell_escape_single_quoted(s: &str) -> String {
    s.replace('\'', "'\\''")
}

struct DbConn {
    ssh_host_id: String,
    engine: String,
    host: String,
    port: i64,
    database: String,
    username: String,
    password: Option<String>,
}

async fn load_credential_secret(
    state: &AppState,
    credential_id: &str,
) -> Result<Option<String>, AppError> {
    let row: Option<(Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT ciphertext, nonce FROM credentials WHERE id = ?")
            .bind(credential_id)
            .fetch_optional(state.vault.pool())
            .await
            .map_err(db)?;

    let Some((ct, nonce)) = row else {
        return Ok(None);
    };
    let plain = state
        .vault
        .open_secret(&ct, &nonce, &format!("cred:{credential_id}"))
        .await?;
    String::from_utf8(plain)
        .map_err(|e| AppError::Crypto {
            message: e.to_string(),
        })
        .map(Some)
}

async fn load_db_connection(state: &AppState, connection_id: &str) -> Result<DbConn, AppError> {
    let row: Option<(
        Option<String>,
        String,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT host_id, engine, host, port, database_name, username, credential_id FROM db_connections WHERE id = ?",
    )
    .bind(connection_id)
    .fetch_optional(state.vault.pool())
    .await
    .map_err(db)?;

    let Some((ssh_host_id, engine, host, port, database, username, credential_id)) = row else {
        return Err(AppError::NotFound {
            entity: "db_connection".into(),
            id: Some(connection_id.to_string()),
        });
    };

    let ssh_host = ssh_host_id.ok_or_else(|| AppError::Validation {
        field: "hostId".into(),
        message: "DB connection must be bound to an SSH host for remote CLI queries".into(),
    })?;

    let password = if let Some(cid) = credential_id {
        load_credential_secret(state, &cid).await?
    } else {
        None
    };

    Ok(DbConn {
        ssh_host_id: ssh_host,
        engine: engine.clone(),
        host: host.unwrap_or_else(|| "127.0.0.1".into()),
        port: port.unwrap_or({
            if matches!(engine.as_str(), "mysql" | "mariadb") {
                3306
            } else {
                5432
            }
        }),
        database: database.unwrap_or_default(),
        username: username.unwrap_or_else(|| {
            if matches!(engine.as_str(), "mysql" | "mariadb") {
                "root".into()
            } else {
                "postgres".into()
            }
        }),
        password,
    })
}

/// Quote a value for a POSIX shell.
fn sq(s: &str) -> String {
    format!("'{}'", shell_escape_single_quoted(s))
}

/// A remote CLI invocation plus the secret to feed it on stdin.
///
/// Passwords are read by the remote shell with `read` and exported, so they never appear in the
/// process arguments that every user on the server can see with `ps`.
pub(crate) struct DbCommand {
    pub script: String,
    pub stdin: Option<zeroize::Zeroizing<Vec<u8>>>,
}

fn with_secret_env(var: &str, password: &Option<String>, body: String) -> DbCommand {
    match password.as_deref().filter(|p| !p.is_empty()) {
        Some(p) => {
            let mut input = p.as_bytes().to_vec();
            input.push(b'\n');
            DbCommand {
                // Run under `sh` so this works whatever the user's login shell is (bash, zsh, fish...).
                script: format!(
                    "sh -c {}",
                    sq(&format!("IFS= read -r {var}; export {var}; {body}"))
                ),
                stdin: Some(zeroize::Zeroizing::new(input)),
            }
        }
        None => DbCommand {
            script: body,
            stdin: None,
        },
    }
}

fn parse_tsv(out: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        return (vec![], vec![]);
    }
    let headers = lines[0].split('\t').map(|s| s.to_string()).collect();
    let rows = lines[1..]
        .iter()
        .map(|l| l.split('\t').map(|s| s.to_string()).collect())
        .collect();
    (headers, rows)
}

fn looks_like_select(sql: &str) -> bool {
    let t = sql.trim().to_uppercase();
    t.starts_with("SELECT")
        || t.starts_with("WITH")
        || t.starts_with("SHOW")
        || t.starts_with("DESCRIBE")
        || t.starts_with("DESC ")
}

fn build_db_cmd(conn: &DbConn, sql: &str, structured: bool) -> Result<DbCommand, AppError> {
    let host = sq(&conn.host);
    let port = conn.port;
    match conn.engine.as_str() {
        "postgres" | "postgresql" => {
            let fmt = if structured {
                "-A -F $'\\t' --pset footer=off"
            } else {
                ""
            };
            let body = format!(
                "psql -w -h {host} -p {port} -U {} -d {} {fmt} -c {} 2>&1",
                sq(&conn.username),
                sq(&conn.database),
                sq(sql)
            );
            Ok(with_secret_env("PGPASSWORD", &conn.password, body))
        }
        "mysql" | "mariadb" => {
            let db_arg = if conn.database.is_empty() {
                String::new()
            } else {
                format!(" {}", sq(&conn.database))
            };
            let batch = if structured { "-B" } else { "" };
            let body = format!(
                "mysql -h {host} -P {port} -u {}{db_arg} {batch} -e {} 2>&1",
                sq(&conn.username),
                sq(sql)
            );
            Ok(with_secret_env("MYSQL_PWD", &conn.password, body))
        }
        "redis" => {
            let cmd_name = sql.split_whitespace().next().unwrap_or("").to_uppercase();
            let blocked = [
                "CONFIG",
                "SLAVEOF",
                "REPLICAOF",
                "MODULE",
                "EVAL",
                "EVALSHA",
                "DEBUG",
                "SHUTDOWN",
                "SCRIPT",
            ];
            if blocked.contains(&cmd_name.as_str()) {
                return Err(AppError::Validation {
                    field: "sql".into(),
                    message: format!("forbidden Redis command: {cmd_name}"),
                });
            }
            // Each word is its own quoted argument (redis-cli expects `GET key`, not "GET key").
            let args = sql.split_whitespace().map(sq).collect::<Vec<_>>().join(" ");
            let body = format!("redis-cli -h {host} -p {port} {args} 2>&1");
            Ok(with_secret_env("REDISCLI_AUTH", &conn.password, body))
        }
        "mongo" | "mongodb" => {
            let uri = format!("mongodb://{}:{}/{}", conn.host, port, conn.database);
            Ok(DbCommand {
                script: format!("mongosh --quiet {} --eval {} 2>&1", sq(&uri), sq(sql)),
                stdin: None,
            })
        }
        "sqlite" => {
            let sql_upper = sql.to_uppercase();
            if sql_upper.contains(".SHELL")
                || sql_upper.contains(".SYSTEM")
                || sql_upper.contains(".LOAD")
            {
                return Err(AppError::Validation {
                    field: "sql".into(),
                    message: "disallowed SQLite dot shell commands".into(),
                });
            }
            Ok(DbCommand {
                script: format!("sqlite3 {} {} 2>&1", sq(&conn.database), sq(sql)),
                stdin: None,
            })
        }
        other => Err(AppError::Validation {
            field: "engine".into(),
            message: format!("unsupported engine: {other}"),
        }),
    }
}

async fn exec_db(
    state: &AppState,
    conn: &DbConn,
    sql: &str,
    structured: bool,
) -> Result<(String, Option<(Vec<String>, Vec<Vec<String>>)>, i64), AppError> {
    let cmd = build_db_cmd(conn, sql, structured)?;
    let started = chrono::Utc::now().timestamp_millis();
    let out = state
        .connections
        .exec_command_with_stdin(
            &conn.ssh_host_id,
            &cmd.script,
            cmd.stdin.as_ref().map(|v| v.as_slice()),
        )
        .await?;
    let duration = chrono::Utc::now().timestamp_millis() - started;

    let lower = out.to_lowercase();
    let is_error = out.lines().any(|l| {
        let t = l.trim();
        t.starts_with("ERROR")
            || t.starts_with("error:")
            || t.contains("Access denied for user")
            || t.contains("FATAL:")
    });
    if is_error && !structured {
        return Err(AppError::Validation {
            field: "sql".into(),
            message: out.trim().to_string(),
        });
    }
    if is_error && structured && !out.lines().any(|l| l.contains('\t')) {
        return Err(AppError::Validation {
            field: "sql".into(),
            message: out.trim().to_string(),
        });
    }
    let _ = lower;

    let parsed = if structured {
        let (headers, rows) = parse_tsv(&out);
        if headers.is_empty() {
            None
        } else {
            Some((headers, rows))
        }
    } else {
        None
    };

    Ok((out, parsed, duration))
}

#[tauri::command]
pub async fn db_connections_list(state: State<'_, Arc<AppState>>) -> Result<Vec<Value>, AppError> {
    let rows: Vec<(
        String,
        Option<String>,
        String,
        String,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, host_id, engine, name, host, port, database_name, username FROM db_connections ORDER BY name",
    )
    .fetch_all(state.vault.pool())
    .await
    .map_err(db)?;
    Ok(rows
        .into_iter()
        .map(
            |(id, host_id, engine, name, host, port, database_name, username)| {
                json!({
                    "id": id, "hostId": host_id, "engine": engine, "name": name,
                    "host": host, "port": port, "database": database_name, "username": username
                })
            },
        )
        .collect())
}

#[tauri::command]
pub async fn db_connections_upsert(
    state: State<'_, Arc<AppState>>,
    conn: Value,
) -> Result<String, AppError> {
    let id = conn["id"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        r#"INSERT INTO db_connections
        (id, host_id, engine, name, host, port, database_name, username, credential_id, ssl_json, tunnel_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
        ON CONFLICT(id) DO UPDATE SET host_id=excluded.host_id, engine=excluded.engine, name=excluded.name,
          host=excluded.host, port=excluded.port, database_name=excluded.database_name,
          username=excluded.username, credential_id=excluded.credential_id, updated_at=excluded.updated_at"#,
    )
    .bind(&id)
    .bind(conn["hostId"].as_str())
    .bind(conn["engine"].as_str().unwrap_or("postgres"))
    .bind(conn["name"].as_str().unwrap_or("db"))
    .bind(conn["host"].as_str())
    .bind(conn["port"].as_i64())
    .bind(conn["database"].as_str())
    .bind(conn["username"].as_str())
    .bind(conn["credentialId"].as_str())
    .bind(now)
    .bind(now)
    .execute(state.vault.pool())
    .await
    .map_err(db)?;
    audit(&state, "db.connection.upsert", Some(&id), "ok", None).await;
    Ok(id)
}

#[tauri::command]
pub async fn db_connections_delete(
    state: State<'_, Arc<AppState>>,
    id: String,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM db_connections WHERE id = ?")
        .bind(&id)
        .execute(state.vault.pool())
        .await
        .map_err(db)?;
    Ok(())
}

#[tauri::command]
pub async fn db_query(
    state: State<'_, Arc<AppState>>,
    connection_id: String,
    sql: String,
) -> Result<Value, AppError> {
    let conn = load_db_connection(&state, &connection_id).await?;
    let structured = looks_like_select(&sql)
        && matches!(
            conn.engine.as_str(),
            "postgres" | "postgresql" | "mysql" | "mariadb"
        );

    let (out, parsed, duration) = exec_db(&state, &conn, &sql, structured).await?;

    let row_count = parsed.as_ref().map(|(_, rows)| rows.len() as i64);
    let hid = Uuid::now_v7().to_string();
    let started = chrono::Utc::now().timestamp_millis() - duration;
    sqlx::query(
        "INSERT INTO query_history (id, db_connection_id, sql, ran_at, duration_ms, row_count, error) VALUES (?, ?, ?, ?, ?, ?, NULL)",
    )
    .bind(&hid)
    .bind(&connection_id)
    .bind(&sql)
    .bind(started)
    .bind(duration)
    .bind(row_count)
    .execute(state.vault.pool())
    .await
    .map_err(db)?;
    audit(
        &state,
        "db.query",
        Some(&connection_id),
        "ok",
        Some(json!({ "ms": duration })),
    )
    .await;

    if let Some((columns, rows)) = parsed {
        Ok(json!({
            "durationMs": duration,
            "columns": columns,
            "rows": rows,
            "rowCount": rows.len(),
            "output": if out.trim().is_empty() { Value::Null } else { Value::String(out) }
        }))
    } else {
        Ok(json!({ "output": out, "durationMs": duration }))
    }
}

#[tauri::command]
pub async fn db_introspect(
    state: State<'_, Arc<AppState>>,
    connection_id: String,
) -> Result<Value, AppError> {
    let conn = load_db_connection(&state, &connection_id).await?;

    let (tables_sql, columns_sql, pk_sql, fk_sql) = match conn.engine.as_str() {
        "postgres" | "postgresql" => (
            "SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') AND table_type='BASE TABLE' ORDER BY table_schema, table_name",
            "SELECT table_schema, table_name, column_name, data_type, is_nullable, COALESCE(column_default,'') FROM information_schema.columns WHERE table_schema NOT IN ('pg_catalog','information_schema') ORDER BY table_schema, table_name, ordinal_position",
            "SELECT kcu.table_schema, kcu.table_name, kcu.column_name FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage kcu ON tc.constraint_name=kcu.constraint_name AND tc.table_schema=kcu.table_schema WHERE tc.constraint_type='PRIMARY KEY'",
            "SELECT kcu.table_schema, kcu.table_name, kcu.column_name, ccu.table_name, ccu.column_name FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage kcu ON tc.constraint_name=kcu.constraint_name AND tc.table_schema=kcu.table_schema JOIN information_schema.constraint_column_usage ccu ON ccu.constraint_name=tc.constraint_name AND ccu.table_schema=tc.table_schema WHERE tc.constraint_type='FOREIGN KEY'",
        ),
        "mysql" | "mariadb" => (
            "SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND table_type='BASE TABLE' ORDER BY table_name",
            "SELECT table_schema, table_name, column_name, data_type, is_nullable, IFNULL(column_default,'') FROM information_schema.columns WHERE table_schema=DATABASE() ORDER BY table_name, ordinal_position",
            "SELECT kcu.table_schema, kcu.table_name, kcu.column_name FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage kcu ON tc.constraint_name=kcu.constraint_name AND tc.table_schema=kcu.table_schema WHERE tc.constraint_type='PRIMARY KEY' AND tc.table_schema=DATABASE()",
            "SELECT kcu.table_schema, kcu.table_name, kcu.column_name, kcu.referenced_table_name, kcu.referenced_column_name FROM information_schema.key_column_usage kcu WHERE kcu.table_schema=DATABASE() AND kcu.referenced_table_name IS NOT NULL",
        ),
        other => {
            return Err(AppError::Validation {
                field: "engine".into(),
                message: format!("introspection not supported for: {other}"),
            })
        }
    };

    let table_rows = exec_db(&state, &conn, tables_sql, true)
        .await?
        .1
        .map(|(_, r)| r)
        .unwrap_or_default();
    let col_rows = exec_db(&state, &conn, columns_sql, true)
        .await?
        .1
        .map(|(_, r)| r)
        .unwrap_or_default();
    let pk_rows = exec_db(&state, &conn, pk_sql, true)
        .await?
        .1
        .map(|(_, r)| r)
        .unwrap_or_default();
    let fk_rows = exec_db(&state, &conn, fk_sql, true)
        .await?
        .1
        .map(|(_, r)| r)
        .unwrap_or_default();

    let mut pk_set = std::collections::HashSet::new();
    for r in &pk_rows {
        if r.len() >= 3 {
            pk_set.insert(format!("{}|{}|{}", r[0], r[1], r[2]));
        }
    }

    let mut fk_map: std::collections::HashMap<String, Vec<Value>> =
        std::collections::HashMap::new();
    for r in &fk_rows {
        if r.len() >= 5 {
            let key = format!("{}|{}", r[0], r[1]);
            fk_map.entry(key).or_default().push(json!({
                "column": r[2],
                "refTable": r[3],
                "refColumn": r[4],
            }));
        }
    }

    let mut col_map: std::collections::HashMap<String, Vec<Value>> =
        std::collections::HashMap::new();
    for r in &col_rows {
        if r.len() >= 6 {
            let key = format!("{}|{}", r[0], r[1]);
            let pk_key = format!("{}|{}|{}", r[0], r[1], r[2]);
            col_map.entry(key).or_default().push(json!({
                "name": r[2],
                "dataType": r[3],
                "nullable": r[4] == "YES",
                "defaultValue": if r[5].is_empty() { Value::Null } else { Value::String(r[5].clone()) },
                "isPrimaryKey": pk_set.contains(&pk_key),
            }));
        }
    }

    let mut schema_map: std::collections::BTreeMap<String, Vec<Value>> =
        std::collections::BTreeMap::new();
    for r in &table_rows {
        if r.len() >= 2 {
            let schema = r[0].clone();
            let table = r[1].clone();
            let key = format!("{schema}|{table}");
            let fks = fk_map.remove(&key).unwrap_or_default();
            let columns = col_map.remove(&key).unwrap_or_default();
            schema_map.entry(schema.clone()).or_default().push(json!({
                "name": table,
                "schema": schema,
                "columns": columns,
                "foreignKeys": fks,
            }));
        }
    }

    let schemas: Vec<Value> = schema_map
        .into_iter()
        .map(|(name, tables)| json!({ "name": name, "tables": tables }))
        .collect();

    Ok(json!({ "schemas": schemas }))
}

#[tauri::command]
pub async fn db_table_preview(
    state: State<'_, Arc<AppState>>,
    connection_id: String,
    table: String,
    schema: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Value, AppError> {
    let conn = load_db_connection(&state, &connection_id).await?;
    let lim = limit.unwrap_or(100).clamp(1, 1000);
    let off = offset.unwrap_or(0).max(0);

    let sql = match conn.engine.as_str() {
        "postgres" | "postgresql" => {
            let sch = schema.as_deref().unwrap_or("public");
            let tbl = table.replace('"', "\"\"");
            let sch_esc = sch.replace('"', "\"\"");
            format!("SELECT * FROM \"{sch_esc}\".\"{tbl}\" LIMIT {lim} OFFSET {off}")
        }
        "mysql" | "mariadb" => {
            let tbl = table.replace('`', "``");
            format!("SELECT * FROM `{tbl}` LIMIT {lim} OFFSET {off}")
        }
        other => {
            return Err(AppError::Validation {
                field: "engine".into(),
                message: format!("preview not supported for: {other}"),
            })
        }
    };

    let (_, parsed, duration) = exec_db(&state, &conn, &sql, true).await?;
    let Some((columns, rows)) = parsed else {
        return Err(AppError::Validation {
            field: "table".into(),
            message: "no data returned".into(),
        });
    };

    Ok(json!({
        "columns": columns,
        "rows": rows,
        "rowCount": rows.len(),
        "durationMs": duration,
    }))
}

#[tauri::command]
pub async fn db_detect(
    state: State<'_, Arc<AppState>>,
    host_id: String,
) -> Result<Value, AppError> {
    let script = r#"
check_port() {
    port_hex=$(printf "%04X" $1)
    if grep -E "[0-9A-F]{8}:${port_hex} " /proc/net/tcp >/dev/null 2>&1; then
        return 0
    fi
    if command -v ss >/dev/null 2>&1; then
        ss -tln | grep -q ":$1 " && return 0
    fi
    if command -v netstat >/dev/null 2>&1; then
        netstat -tln | grep -q ":$1 " && return 0
    fi
    return 1
}

# 1. Postgres (5432)
if check_port 5432 || command -v psql >/dev/null 2>&1; then
    dbs=""
    if command -v psql >/dev/null 2>&1; then
        dbs=$(psql -h 127.0.0.1 -p 5432 -U postgres -d postgres -t -A -c "SELECT datname FROM pg_database WHERE datistemplate = false;" 2>/dev/null)
        if [ -z "$dbs" ]; then
            dbs=$(psql -U postgres -d postgres -t -A -c "SELECT datname FROM pg_database WHERE datistemplate = false;" 2>/dev/null)
        fi
    fi
    if [ -z "$dbs" ]; then
        dbs="postgres"
    fi
    echo "postgres:127.0.0.1:5432:postgres:$(echo "$dbs" | tr '\n' ',' | sed 's/,$//')"
fi

# 2. MySQL / MariaDB (3306)
if check_port 3306 || command -v mysql >/dev/null 2>&1; then
    dbs=""
    if command -v mysql >/dev/null 2>&1; then
        dbs=$(mysql -h 127.0.0.1 -P 3306 -u root -e "SHOW DATABASES;" -B -N 2>/dev/null)
        if [ -z "$dbs" ]; then
            dbs=$(mysql -u root -e "SHOW DATABASES;" -B -N 2>/dev/null)
        fi
    fi
    if [ -z "$dbs" ]; then
        dbs="mysql"
    fi
    echo "mysql:127.0.0.1:3306:root:$(echo "$dbs" | tr '\n' ',' | sed 's/,$//')"
fi

# 3. Redis (6379)
if check_port 6379 || command -v redis-cli >/dev/null 2>&1; then
    dbs=""
    if command -v redis-cli >/dev/null 2>&1; then
        dbs=$(redis-cli -h 127.0.0.1 -p 6379 info keyspace 2>/dev/null | grep -E '^db[0-9]+:' | cut -d: -f1)
    fi
    if [ -z "$dbs" ]; then
        dbs="db0"
    fi
    echo "redis:127.0.0.1:6379::$(echo "$dbs" | tr '\n' ',' | sed 's/,$//')"
fi

# 4. MongoDB (27017)
if check_port 27017 || command -v mongosh >/dev/null 2>&1 || command -v mongo >/dev/null 2>&1; then
    dbs=""
    if command -v mongosh >/dev/null 2>&1; then
        dbs=$(mongosh --quiet --eval "db.adminCommand('listDatabases').databases.map(d => d.name).join(',')" 2>/dev/null)
    elif command -v mongo >/dev/null 2>&1; then
        dbs=$(mongo --quiet --eval "db.adminCommand('listDatabases').databases.map(d => d.name).join(',')" 2>/dev/null)
    fi
    if [ -z "$dbs" ]; then
        dbs="admin"
    fi
    echo "mongodb:127.0.0.1:27017:root:$(echo "$dbs" | tr '\n' ',' | sed 's/,$//')"
fi
"#;

    let out = state.connections.exec_command(&host_id, script).await?;
    let mut detected = Vec::new();

    for line in out.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 5 {
            let engine = parts[0].to_string();
            let host = parts[1].to_string();
            let port = parts[2].parse::<i64>().unwrap_or(0);
            let username = parts[3].to_string();
            let databases: Vec<String> = parts[4]
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            detected.push(json!({
                "engine": engine,
                "host": host,
                "port": port,
                "username": username,
                "databases": databases,
            }));
        }
    }

    Ok(Value::Array(detected))
}

#[tauri::command]
pub async fn saved_queries_list(
    state: State<'_, Arc<AppState>>,
    connection_id: String,
) -> Result<Vec<Value>, AppError> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, name, sql FROM saved_queries WHERE db_connection_id = ? ORDER BY name",
    )
    .bind(&connection_id)
    .fetch_all(state.vault.pool())
    .await
    .map_err(db)?;
    Ok(rows
        .into_iter()
        .map(|(id, name, sql)| json!({ "id": id, "name": name, "sql": sql }))
        .collect())
}

#[tauri::command]
pub async fn saved_queries_upsert(
    state: State<'_, Arc<AppState>>,
    query: Value,
) -> Result<String, AppError> {
    let id = query["id"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        r#"INSERT INTO saved_queries (id, db_connection_id, name, sql, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET name=excluded.name, sql=excluded.sql, updated_at=excluded.updated_at"#,
    )
    .bind(&id)
    .bind(query["connectionId"].as_str().unwrap_or(""))
    .bind(query["name"].as_str().unwrap_or("query"))
    .bind(query["sql"].as_str().unwrap_or(""))
    .bind(now)
    .bind(now)
    .execute(state.vault.pool())
    .await
    .map_err(db)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(engine: &str, password: Option<&str>) -> DbConn {
        DbConn {
            ssh_host_id: "h".into(),
            engine: engine.into(),
            host: "127.0.0.1".into(),
            port: 5432,
            database: "app".into(),
            username: "admin".into(),
            password: password.map(Into::into),
        }
    }

    #[test]
    fn passwords_go_to_stdin_not_argv() {
        for (engine, var) in [
            ("postgres", "PGPASSWORD"),
            ("mysql", "MYSQL_PWD"),
            ("redis", "REDISCLI_AUTH"),
        ] {
            let cmd = build_db_cmd(&conn(engine, Some("p@ss w'rd")), "SELECT 1", true).unwrap();
            assert!(!cmd.script.contains("p@ss"), "{engine}: {}", cmd.script);
            assert!(
                cmd.script
                    .starts_with(&format!("sh -c 'IFS= read -r {var}; export {var}; ")),
                "{engine}: {}",
                cmd.script
            );
            assert_eq!(
                cmd.stdin.as_deref().map(|v| v.as_slice()),
                Some(&b"p@ss w'rd\n"[..])
            );
        }
    }

    #[test]
    fn no_password_means_no_stdin() {
        let cmd = build_db_cmd(&conn("postgres", None), "SELECT 1", false).unwrap();
        assert!(cmd.stdin.is_none());
        assert!(cmd.script.starts_with("psql -w "));
    }

    #[test]
    fn connection_fields_are_quoted() {
        let mut c = conn("postgres", None);
        c.host = "db; id".into();
        c.username = "$(id)".into();
        c.database = "x' ; id #".into();
        let cmd = build_db_cmd(&c, "SELECT 1", false).unwrap();
        assert!(cmd.script.contains("-h 'db; id'"), "{}", cmd.script);
        assert!(cmd.script.contains("-U '$(id)'"), "{}", cmd.script);
        assert!(cmd.script.contains("-d 'x'\\'' ; id #'"), "{}", cmd.script);
    }

    #[test]
    fn redis_splits_arguments_and_blocks_dangerous_commands() {
        let cmd = build_db_cmd(&conn("redis", None), "GET  my:key", false).unwrap();
        assert!(
            cmd.script.ends_with("'GET' 'my:key' 2>&1"),
            "{}",
            cmd.script
        );
        assert!(build_db_cmd(&conn("redis", None), "config set dir /", false).is_err());
    }

    #[test]
    fn sqlite_dot_commands_blocked() {
        assert!(build_db_cmd(&conn("sqlite", None), ".shell id", false).is_err());
        assert!(build_db_cmd(&conn("sqlite", None), ".system id", false).is_err());
    }
}
