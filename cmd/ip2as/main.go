package main

import (
	"context"
	"log"
	"net"

	"github.com/f110/ip2as"
	"google.golang.org/grpc"
)

type Server struct{}

func (s *Server) ToAs(ctx context.Context, req *ip2as.ToAsRequest) (*ip2as.ToAsResponse, error) {
	return nil, nil
}

func main() {
	l, err := net.Listen("tcp", ":8888")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	ip2as.RegisterIp2AsServer(s, &Server{})
	if err := s.Serve(l); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
