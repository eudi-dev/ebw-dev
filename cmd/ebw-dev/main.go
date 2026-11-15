// Command ebw-dev serves the business wallet demo: the agent cases, the
// scenarios and the issuer page.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eudi-dev/ebw-dev/internal/demo"
)

// version is set at build time with -ldflags "-X main.version=<version>".
var version = "dev"

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func main() {
	listen := flag.String("listen", env("EBW_DEV_LISTEN", "127.0.0.1:28090"), "listen address")
	publicURL := flag.String("public-url", env("EBW_DEV_PUBLIC_URL", "http://localhost:28090"), "base URL for browsers and the wallet, with an optional path prefix")
	walletURL := flag.String("wallet-url", env("EBW_DEV_WALLET_URL", "http://localhost:28085"), "base URL of the business wallet for this server")
	walletPublicURL := flag.String("wallet-public-url", env("EBW_DEV_WALLET_PUBLIC_URL", ""), "base URL of the business wallet for browsers (default: the wallet URL)")
	brandDir := flag.String("brand-dir", env("EBW_DEV_BRAND_DIR", "brand"), "directory with logo.svg")
	flag.Parse()

	server, err := demo.NewServer(demo.Config{
		PublicURL:       *publicURL,
		WalletURL:       *walletURL,
		WalletPublicURL: *walletPublicURL,
		BrandDir:        *brandDir,
		Version:         version,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := server.LoadTrust(ctx); err != nil {
		log.Printf("The trusted lists of the wallet did not load. The server tries again on the first request. Cause: %v", err)
	}

	httpServer := &http.Server{Addr: *listen, Handler: server, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	log.Printf("ebw-dev listens on %s. Public URL: %s. Wallet: %s.", *listen, *publicURL, *walletURL)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
