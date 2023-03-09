package main

import (
	"collector/internal"
	"collector/pkg/version"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Print version information
	log.Printf("GitCommitInfo:%s\n", version.Version())

	app, err := internal.NewApp()
	if err != nil {
		log.Fatalf("Failed to create application: %v", err)
	}

	err = app.Run()
	if err != nil {
		log.Fatalf("Failed to run application: %v", err)
	}

	// Register signal handler
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	// Block until a signal is received.
	select {
	case sig := <-sigCh:
		log.Printf("Received signal [%v], and will exit", sig)
		if err = app.Shutdown(); err != nil {
			log.Printf("Error happened when shutting down: %v", err)
			os.Exit(1)
		}
	}
}
