package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/config"
	"github.com/Sushidesu486/KubeGrant/internal/httpapi"
	"github.com/Sushidesu486/KubeGrant/internal/identity"
	"github.com/Sushidesu486/KubeGrant/internal/storage"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) > 1 {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
		var err error
		switch os.Args[1] {
		case "backup":
			err = backup(os.Args[2:])
		case "clear-sessions":
			if len(os.Args) != 2 {
				err = errors.New("clear-sessions takes no arguments")
			} else {
				err = clearSessions()
			}
		default:
			err = errors.New("unknown command")
		}
		if err != nil {
			logger.Error("command failed", "error", err)
			os.Exit(1)
		}
		logger.Info("command complete")
		return
	}
	if err := run(logger); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	store, err := storage.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	var authenticator identity.Authenticator
	if len(cfg.LDAP.URLs) > 0 {
		authenticator, err = identity.NewFreeIPA(cfg.LDAP)
		if err != nil {
			return err
		}
	}
	handler, err := httpapi.NewHandler(httpapi.Options{StaticDir: cfg.StaticDir, PublicURL: cfg.PublicURL,
		SecureCookies: cfg.SecureCookies, Authenticator: authenticator, Store: store, SessionTTL: cfg.SessionTTL,
		GrantMaxTTL: cfg.GrantMaxTTL, ClusterID: cfg.ClusterID, PermissionRef: cfg.PermissionRef})
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: cfg.HTTPAddr, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result := make(chan error, 1)
	go func() {
		logger.Info("starting kubegrant", "address", cfg.HTTPAddr, "authentication_configured", authenticator != nil)
		result <- server.ListenAndServe()
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		if err := <-result; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		logger.Info("shutdown complete")
		return nil
	}
}
