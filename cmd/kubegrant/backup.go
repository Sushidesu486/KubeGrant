package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Sushidesu486/KubeGrant/internal/config"
	"github.com/Sushidesu486/KubeGrant/internal/storage"
)

func backup(args []string) error {
	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	output := flags.String("output", "", "new backup file path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *output == "" || flags.NArg() != 0 {
		return errors.New("usage: kubegrant backup --output NEW_FILE")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if _, err = os.Stat(cfg.DatabasePath); err != nil {
		return err
	}
	store, err := storage.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if *output != "-" {
		return store.Backup(ctx, *output)
	}
	dir, err := os.MkdirTemp(filepath.Dir(cfg.DatabasePath), ".backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "snapshot.db")
	if err = store.Backup(ctx, path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(os.Stdout, f)
	return err
}

func clearSessions() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if _, err = os.Stat(cfg.DatabasePath); err != nil {
		return err
	}
	s, err := storage.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.ClearSessions(ctx, time.Now().UTC())
}
