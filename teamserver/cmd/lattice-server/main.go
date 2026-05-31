// lattice-server — Lattice team server entry point.
//
// Starts three listeners concurrently:
//   - gRPC server (agent-facing AgentService + operator-facing OperatorService)
//   - REST/OpenAPI server (Gin, operator tooling and health check)
//   - NATS JetStream connection (internal message bus between transport listeners
//     and the core task scheduler)
//
// Transport plugins (Go .so files) are loaded at startup from the --plugins
// directory. Each plugin exports a lattice.Transport interface.

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/muayruler1231/acr-lab/teamserver/internal/api"
	"github.com/muayruler1231/acr-lab/teamserver/internal/core"
	"github.com/muayruler1231/acr-lab/teamserver/internal/store"
)

func main() {
	grpcAddr   := flag.String("grpc", ":50051", "gRPC listen address")
	restAddr   := flag.String("rest", ":8080",  "REST/OpenAPI listen address")
	natsURL    := flag.String("nats", "nats://127.0.0.1:4222", "NATS server URL")
	pluginDir  := flag.String("plugins", "./plugins", "transport plugin directory")
	profileDir := flag.String("profiles", "./profiles", "profile directory")
	flag.Parse()

	db, err := store.Open("lattice.db")
	if err != nil {
		log.Fatalf("store.Open: %v", err)
	}
	defer db.Close()

	scheduler, err := core.NewScheduler(db, *natsURL)
	if err != nil {
		log.Fatalf("core.NewScheduler: %v", err)
	}

	if err := core.LoadTransportPlugins(scheduler, *pluginDir); err != nil {
		log.Printf("warn: transport plugin load: %v", err)
	}

	if err := core.LoadDefaultProfile(scheduler, *profileDir); err != nil {
		log.Printf("warn: profile load: %v", err)
	}

	go func() {
		if err := api.ServeGRPC(*grpcAddr, scheduler); err != nil {
			log.Fatalf("api.ServeGRPC: %v", err)
		}
	}()

	go func() {
		if err := api.ServeREST(*restAddr, scheduler); err != nil {
			log.Fatalf("api.ServeREST: %v", err)
		}
	}()

	log.Printf("lattice-server started  grpc=%s  rest=%s", *grpcAddr, *restAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
}
