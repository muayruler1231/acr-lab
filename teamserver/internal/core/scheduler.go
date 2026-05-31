// Package core implements the Lattice task scheduler and agent lifecycle manager.
//
// The scheduler owns two primary data structures:
//   - agent table: in-memory map of AgentID → AgentState (backed by SQLite)
//   - task queue: per-agent FIFO queue of pending tasks
//
// Transport plugins and the gRPC AgentService both push tasks into the queue
// via IssueTask. The TaskStream RPC drains the queue per agent. Results flow
// back through ResultCallback, which notifies NATS subscribers and updates
// the SQLite store.

package core

import (
	"fmt"
	"plugin"

	"github.com/muayruler1231/acr-lab/teamserver/internal/store"
)

// Transport is the interface each transport plugin must export as "Transport".
type Transport interface {
	Name() string
	Listen(addr string, scheduler TaskIssuer) error
	Stop() error
}

// TaskIssuer is the subset of Scheduler exposed to transport plugins.
type TaskIssuer interface {
	IssueTask(agentID string, task *store.Task) error
	RegisterAgent(info *store.AgentInfo) error
}

// Scheduler coordinates agent lifecycle and task dispatch.
type Scheduler struct {
	db      *store.DB
	natsURL string
	// TODO: add NATS JetStream connection, gRPC server state, plugin registry
}

func NewScheduler(db *store.DB, natsURL string) (*Scheduler, error) {
	return &Scheduler{db: db, natsURL: natsURL}, nil
}

// IssueTask enqueues a task for the given agent.
func (s *Scheduler) IssueTask(agentID string, task *store.Task) error {
	// TODO: validate agent exists, persist to SQLite, publish to NATS
	return s.db.EnqueueTask(agentID, task)
}

// RegisterAgent upserts agent metadata and sets state to ACTIVE.
func (s *Scheduler) RegisterAgent(info *store.AgentInfo) error {
	// TODO: host-lock token validation, OTA key burn on first check-in
	return s.db.UpsertAgent(info)
}

// LoadTransportPlugins loads all .so files from pluginDir as transport plugins.
func LoadTransportPlugins(s *Scheduler, pluginDir string) error {
	// TODO: walk pluginDir, open each .so with plugin.Open, look up "Transport"
	_ = plugin.Open // ensure import is used
	return fmt.Errorf("transport plugin loading not yet implemented")
}

// LoadDefaultProfile reads the default.json profile from profileDir and applies it.
func LoadDefaultProfile(s *Scheduler, profileDir string) error {
	// TODO: read profileDir/default.json, parse 3-plane struct, apply to scheduler
	return nil
}
