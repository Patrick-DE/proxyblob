// Package main implements the SOCKS proxy agent.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"

	"github.com/Azure/azure-storage-blob-go/azblob"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"proxyblob/pkg/protocol"
	proxy "proxyblob/pkg/proxy/socks"
	"proxyblob/pkg/transport"
)

// Exit codes.
const (
	Success                  = 0 // success
	ErrContextCanceled       = 1 // context canceled
	ErrNoConnectionString    = 2 // missing connection string
	ErrConnectionStringError = 3 // invalid connection string
	ErrInfoBlobError         = 4 // info blob write failed
	ErrContainerNotFound     = 5 // container not found
)

// ConnString holds the Azure connection string.
// Can be set at compile time or via command line flag.
var ConnString string

// Blob names for proxy-agent communication.
const (
	InfoBlobName     = "info"     // agent metadata
	RequestBlobName  = "request"  // proxy-to-agent traffic
	ResponseBlobName = "response" // agent-to-proxy traffic
)

// InfoKey defines the XOR encryption key for agent information
// Security Note: Changing this key requires synchronized updates on both proxy and agent
var (
	InfoKey = []byte{0xDE, 0xAD, 0xB1, 0x0B}
)

// Agent manages proxy operations and blob storage communication.
type Agent struct {
	ContainerURL azblob.ContainerURL // Azure container access
	Handler      *proxy.SocksHandler // SOCKS handler
}

// NewAgent creates an agent from a connection string.
func NewAgent(ctx context.Context, connString string) (*Agent, int) {
	storageURL, containerID, sasToken, errCode := ParseConnectionString(connString)
	if errCode != Success {
		return nil, errCode
	}

	pipeline := azblob.NewPipeline(
		azblob.NewAnonymousCredential(),
		azblob.PipelineOptions{},
	)

	fullURL := fmt.Sprintf("%s/%s?%s", storageURL, containerID, sasToken)
	containerURL, err := url.Parse(fullURL)
	if err != nil {
		return nil, ErrConnectionStringError
	}

	container := azblob.NewContainerURL(*containerURL, pipeline)
	blobTransport := transport.NewBlobTransport(
		container.NewBlockBlobURL(RequestBlobName),  // read
		container.NewBlockBlobURL(ResponseBlobName), // write
	)
	handler := proxy.NewSocksHandler(ctx, blobTransport)

	agent := &Agent{
		ContainerURL: container,
		Handler:      handler,
	}

	return agent, Success
}

// Start begins processing proxy requests.
func (a *Agent) Start(ctx context.Context) int {
	// Push agent information to blob storage
	if err := a.WriteInfoBlob(ctx); err != Success {
		a.Stop()
		return ErrContainerNotFound
	}

	// Start the container monitoring goroutine
	go a.healthCheck(ctx)

	// Start the handler
	a.Handler.Start("")

	// Wait for handler context to be done
	<-a.Handler.Ctx.Done()

	// Check if context was canceled externally
	if errors.Is(ctx.Err(), context.Canceled) {
		return ErrContextCanceled
	}

	return Success
}

// Stop terminates agent operations.
func (a *Agent) Stop() {
	a.Handler.Stop()
}

// healthCheck verifies container existence every 30s and stops the agent if it's unavailable.
func (a *Agent) healthCheck(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			blobURL := a.ContainerURL.NewBlockBlobURL(InfoBlobName)
			_, err := blobURL.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})
			if err != nil {
				if storageErr, ok := err.(azblob.StorageError); ok {
					if storageErr.ServiceCode() == azblob.ServiceCodeContainerNotFound ||
						storageErr.ServiceCode() == azblob.ServiceCodeContainerBeingDeleted {
						a.Stop()
						return
					}
				}
			}
		}
	}
}

// WriteInfoBlob updates agent metadata.
func (a *Agent) WriteInfoBlob(ctx context.Context) int {
	info := GetCurrentInfo()
	encryptedInfo := protocol.Xor([]byte(info), InfoKey)

	blobURL := a.ContainerURL.NewBlockBlobURL(InfoBlobName)
	_, err := blobURL.Upload(
		ctx,
		bytes.NewReader(encryptedInfo),
		azblob.BlobHTTPHeaders{ContentType: "text/plain"},
		azblob.Metadata{},
		azblob.BlobAccessConditions{},
		azblob.DefaultAccessTier,
		nil,
		azblob.ClientProvidedKeyOptions{},
		azblob.ImmutabilityPolicyOptions{},
	)

	if err != nil {
		// Check for context cancellation first
		if errors.Is(ctx.Err(), context.Canceled) {
			return ErrContextCanceled
		}

		// Check for container deletion
		if storageErr, ok := err.(azblob.StorageError); ok {
			if storageErr.ServiceCode() == azblob.ServiceCodeContainerNotFound ||
				storageErr.ServiceCode() == azblob.ServiceCodeContainerBeingDeleted {
				return ErrContainerNotFound
			}
			// Other storage errors
			return ErrInfoBlobError
		}

		return ErrInfoBlobError
	}

	return Success
}

// ParseConnectionString extracts storage URL, container ID and SAS token from a connection string.
func ParseConnectionString(connString string) (string, string, string, int) {
	// Check for empty string first
	if connString == "" {
		return "", "", "", ErrNoConnectionString
	}

	// Try to decode the base64 encoded string
	decoded, err := base64.RawStdEncoding.DecodeString(connString)
	if err != nil {
		return "", "", "", ErrConnectionStringError
	}

	// Parse the URL and extract components
	u, err := url.Parse(string(decoded))
	if err != nil {
		return "", "", "", ErrConnectionStringError
	}

	// Extract path components and query string
	path := strings.TrimPrefix(u.Path, "/")
	if path == "" {
		return "", "", "", ErrConnectionStringError
	}

	if u.RawQuery == "" {
		return "", "", "", ErrConnectionStringError
	}

	// Return the storage URL, container ID and SAS token
	storageURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	return storageURL, path, u.RawQuery, Success
}

// GetCurrentInfo returns username@hostname.
func GetCurrentInfo() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	currentUser, err := user.Current()
	if err != nil {
		currentUser = &user.User{
			Username: "unknown",
		}
	}

	return fmt.Sprintf("%s@%s", currentUser.Username, hostname)
}

// init configures logging with zerolog
// Sets up console output and INFO level logging
func init() {
	// Configure logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// Use a more human-friendly output for console
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

// main is the entry point for the agent process
// Handles command-line flags, signal management, and agent lifecycle
func main() {
	// Parse command line flags
	flag.StringVar(&ConnString, "c", ConnString, "Connection string")
	flag.Parse()

	if ConnString == "" {
		os.Exit(ErrNoConnectionString)
	}

	// Create context that can be cancelled with CTRL+C
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle SIGINT (CTRL+C) and SIGTERM
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	// Create the agent
	agent, err := NewAgent(ctx, ConnString)
	if err != Success {
		os.Exit(err)
	}

	// Start the agent
	ErrCode := agent.Start(ctx)
	os.Exit(ErrCode)
}
