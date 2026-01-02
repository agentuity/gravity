package heartbeat

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	_logger "github.com/agentuity/go-common/logger"
)

const (
	HeartbeatTimeoutSeconds = 30
	HeartbeatCheckInterval  = 5 * time.Second
	ExitCodeNoHeartbeat     = 254 // -2 in unsigned
)

type Server struct {
	logger       _logger.Logger
	listener     net.Listener
	server       *http.Server
	port         int
	lastBeat     time.Time
	lastBeatMu   sync.RWMutex
	cancel       context.CancelFunc
	shutdownOnce sync.Once
}

func NewServer(logger _logger.Logger) (*Server, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	s := &Server{
		logger:   logger,
		listener: listener,
		port:     port,
		lastBeat: time.Now(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/heartbeat", s.handleHeartbeat)

	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return s, nil
}

func (s *Server) Port() int {
	return s.port
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.lastBeatMu.Lock()
	s.lastBeat = time.Now()
	s.lastBeatMu.Unlock()

	s.logger.Trace("Received heartbeat")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (s *Server) Start(ctx context.Context) error {
	monitorCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	go s.monitorHeartbeat(monitorCtx)

	go func() {
		<-ctx.Done()
		s.Shutdown()
	}()

	s.logger.Debug("Heartbeat server listening on port %d", s.port)
	if err := s.server.Serve(s.listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("heartbeat server error: %w", err)
	}
	return nil
}

func (s *Server) monitorHeartbeat(ctx context.Context) {
	ticker := time.NewTicker(HeartbeatCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.lastBeatMu.RLock()
			elapsed := time.Since(s.lastBeat)
			s.lastBeatMu.RUnlock()

			if elapsed > HeartbeatTimeoutSeconds*time.Second {
				s.logger.Error("No heartbeat received for %v seconds, shutting down", HeartbeatTimeoutSeconds)
				os.Exit(ExitCodeNoHeartbeat)
			}

			s.logger.Trace("Heartbeat check: last beat %v ago", elapsed.Round(time.Second))
		}
	}
}

func (s *Server) Shutdown() {
	s.shutdownOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.server.Shutdown(ctx)
	})
}
