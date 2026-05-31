// Package store manages persistent agent state and task queues via SQLite.
package store

import (
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type AgentInfo struct {
	ID        string
	Hostname  string
	Username  string
	OS        string
	Elevated  bool
	PID       uint32
	PPID      uint32
	Arch      string
	Transport string
	LastSeen  time.Time
	State     string
}

type Task struct {
	ID        string
	AgentID   string
	Type      string
	Payload   []byte
	BofMode   string
	IssuedAt  time.Time
}

type TaskResult struct {
	TaskID      string
	AgentID     string
	Success     bool
	Output      []byte
	Error       string
	CompletedAt time.Time
}

type DB struct {
	sql *sql.DB
}

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		return nil, err
	}
	return &DB{sql: db}, nil
}

func (d *DB) Close() error { return d.sql.Close() }

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS agents (
		id        TEXT PRIMARY KEY,
		hostname  TEXT,
		username  TEXT,
		os        TEXT,
		elevated  INTEGER,
		pid       INTEGER,
		ppid      INTEGER,
		arch      TEXT,
		transport TEXT,
		last_seen TEXT,
		state     TEXT
	);

	CREATE TABLE IF NOT EXISTS tasks (
		id         TEXT PRIMARY KEY,
		agent_id   TEXT,
		type       TEXT,
		payload    BLOB,
		bof_mode   TEXT,
		issued_at  TEXT,
		FOREIGN KEY(agent_id) REFERENCES agents(id)
	);

	CREATE TABLE IF NOT EXISTS task_results (
		task_id      TEXT PRIMARY KEY,
		agent_id     TEXT,
		success      INTEGER,
		output       BLOB,
		error        TEXT,
		completed_at TEXT,
		FOREIGN KEY(agent_id) REFERENCES agents(id)
	);
	`)
	return err
}

func (d *DB) UpsertAgent(a *AgentInfo) error {
	_, err := d.sql.Exec(`
	INSERT INTO agents(id,hostname,username,os,elevated,pid,ppid,arch,transport,last_seen,state)
	VALUES(?,?,?,?,?,?,?,?,?,?,?)
	ON CONFLICT(id) DO UPDATE SET
		hostname=excluded.hostname, username=excluded.username,
		os=excluded.os, elevated=excluded.elevated, pid=excluded.pid,
		ppid=excluded.ppid, arch=excluded.arch, transport=excluded.transport,
		last_seen=excluded.last_seen, state=excluded.state`,
		a.ID, a.Hostname, a.Username, a.OS, a.Elevated,
		a.PID, a.PPID, a.Arch, a.Transport,
		a.LastSeen.UTC().Format(time.RFC3339), a.State,
	)
	return err
}

func (d *DB) EnqueueTask(agentID string, t *Task) error {
	_, err := d.sql.Exec(`
	INSERT INTO tasks(id,agent_id,type,payload,bof_mode,issued_at)
	VALUES(?,?,?,?,?,?)`,
		t.ID, agentID, t.Type, t.Payload, t.BofMode,
		t.IssuedAt.UTC().Format(time.RFC3339),
	)
	return err
}

func (d *DB) DequeueTask(agentID string) (*Task, error) {
	row := d.sql.QueryRow(`
	SELECT id,agent_id,type,payload,bof_mode,issued_at
	FROM tasks WHERE agent_id=? ORDER BY issued_at ASC LIMIT 1`, agentID)

	var t Task
	var issuedAt string
	err := row.Scan(&t.ID, &t.AgentID, &t.Type, &t.Payload, &t.BofMode, &issuedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.IssuedAt, _ = time.Parse(time.RFC3339, issuedAt)
	return &t, nil
}

func (d *DB) StoreResult(r *TaskResult) error {
	_, err := d.sql.Exec(`
	INSERT OR REPLACE INTO task_results(task_id,agent_id,success,output,error,completed_at)
	VALUES(?,?,?,?,?,?)`,
		r.TaskID, r.AgentID, r.Success, r.Output, r.Error,
		r.CompletedAt.UTC().Format(time.RFC3339),
	)
	return err
}
