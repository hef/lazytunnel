package main

import (
	"context"
	"github.com/hef/lazytunnel/internal/serverconn"
	"go.uber.org/zap"
	"os"
	"os/signal"
	"sync"
)

func systemContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		cancel()
	}()
	return ctx
}

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	ctx := systemContext()
	serviceDefinitions := []struct {
		role string
		port int
	}{
		{"consul-server", 8500},
		{"nomad", 4646},
		{"vault", 8200},
	}
	wg := sync.WaitGroup{}
	for _, serviceDefinition := range serviceDefinitions {
		tunnel, err := serverconn.New(logger.Named(serviceDefinition.role), serviceDefinition.role, serviceDefinition.port)
		if err != nil {
			logger.Error("error creating role",
				zap.String("role", serviceDefinition.role),
				zap.Int("port", serviceDefinition.port),
				zap.Error(err),
			)
			continue
		}
		wg.Add(1)
		go func() {
			tunnel.Run(ctx)
			wg.Done()
		}()
	}
	wg.Wait()
}
