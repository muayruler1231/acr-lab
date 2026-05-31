// Package api wires the gRPC and REST servers to the core scheduler.
package api

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"

	"google.golang.org/grpc"

	"github.com/muayruler1231/acr-lab/teamserver/internal/core"
	"github.com/muayruler1231/acr-lab/teamserver/internal/store"
	pb "github.com/muayruler1231/acr-lab/teamserver/proto"
)

type agentServer struct {
	pb.UnimplementedAgentServiceServer
	scheduler *core.Scheduler
}

func (s *agentServer) CheckIn(
	ctx context.Context, req *pb.CheckInRequest,
) (*pb.CheckInResponse, error) {
	info := &store.AgentInfo{
		ID:        req.Info.Id,
		Hostname:  req.Info.Hostname,
		Username:  req.Info.Username,
		OS:        req.Info.Os,
		Elevated:  req.Info.Elevated,
		PID:       req.Info.Pid,
		PPID:      req.Info.Ppid,
		Arch:      req.Info.Arch,
		Transport: req.Info.Transport,
		State:     "ACTIVE",
	}
	if err := s.scheduler.RegisterAgent(info); err != nil {
		return nil, fmt.Errorf("RegisterAgent: %w", err)
	}
	// TODO: generate short-lived JWT, pull sleep/jitter from active profile
	return &pb.CheckInResponse{
		SessionToken: "TODO-jwt",
		SleepMs:      60000,
		JitterPct:    15,
	}, nil
}

func (s *agentServer) TaskStream(stream pb.AgentService_TaskStreamServer) error {
	for {
		result, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		log.Printf("task result: agent=%s task=%s ok=%v", result.AgentId, result.TaskId, result.Success)
		// TODO: store result, notify NATS, dequeue next task and Send
		_ = result
	}
}

func ServeGRPC(addr string, scheduler *core.Scheduler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := grpc.NewServer(
		// TODO: add mTLS credentials, rate-limiting interceptor
	)
	pb.RegisterAgentServiceServer(srv, &agentServer{scheduler: scheduler})
	log.Printf("gRPC listening on %s", addr)
	return srv.Serve(ln)
}
