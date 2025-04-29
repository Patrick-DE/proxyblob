// Package main implements the SOCKS proxy server.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-storage-blob-go/azblob"
	"github.com/desertbit/grumble"
	"github.com/google/uuid"
	"github.com/jedib0t/go-pretty/table"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"proxyblob/pkg/protocol"
	proxy "proxyblob/pkg/proxy/server"
	"proxyblob/pkg/transport"
)

// CLI banner with version.
const banner = `
  ____                      ____  _       _     
 |  _ \ _ __ _____  ___   _| __ )| | ___ | |__  
 | |_) | '__/ _ \ \/ / | | |  _ \| |/ _ \| '_ \ 
 |  __/| | | (_) >  <| |_| | |_) | | (_) | |_) |
 |_|   |_|  \___/_/\_\\__, |____/|_|\___/|_.__/ 
                      |___/                     

   SOCKS Proxy over Azure Blob Storage (v1.0)
   ------------------------------------------

`

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

// Config holds Azure Storage credentials.
type Config struct {
	StorageAccountName string `json:"storage_account_name"`  // account ID
	StorageAccountKey  string `json:"storage_account_key"`   // access key
	StorageURL         string `json:"storage_url,omitempty"` // custom endpoint (for development purposes)
}

// StorageManager handles Azure Storage operations.
type StorageManager struct {
	ServiceURL          *azblob.ServiceURL          // storage endpoint
	SharedKeyCredential *azblob.SharedKeyCredential // auth credentials
}

// ContainerInfo tracks proxy agent metadata.
type ContainerInfo struct {
	ID           string    // container ID
	AgentInfo    string    // username@hostname
	ProxyPort    string    // SOCKS port
	CreatedAt    time.Time // creation time
	LastActivity time.Time // last operation
}

// Global state.
var (
	config         *Config         // app config
	storageManager *StorageManager // storage access
	selectedAgent  string          // current agent
	runningProxies sync.Map        // active proxies
)

// LoadConfig reads and parses config file.
func LoadConfig(configPath string) (*Config, error) {
	// Use default config path (./config.json) if none provided
	if configPath == "" {
		configPath = "./config.json"
	}

	// Get absolute path for clearer error messages
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve config path: %v", err)
	}

	// Check if config file exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found at %s", absPath)
	}

	// Read and parse the configuration file
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %v", absPath, err)
	}

	config := new(Config)
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %v", absPath, err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate checks required config fields.
func (config *Config) Validate() error {
	if config.StorageAccountName == "" {
		return fmt.Errorf("storage_account_name is required")
	}
	if config.StorageAccountKey == "" {
		return fmt.Errorf("storage_account_key is required")
	}
	return nil
}

// NewStorageManager creates Azure Storage client.
func NewStorageManager(config *Config) (*StorageManager, error) {
	// Create credentials using the storage account name and key
	credential, err := azblob.NewSharedKeyCredential(
		config.StorageAccountName,
		config.StorageAccountKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage credentials: %v", err)
	}

	// Create a pipeline for storage operations
	pipeline := azblob.NewPipeline(
		credential,
		azblob.PipelineOptions{},
	)

	// Build the service URL for the storage account
	var serviceURL *url.URL
	if config.StorageURL != "" {
		// Use the custom storage URL provided in the config (for Azurite support)
		serviceURL, err = url.Parse(config.StorageURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse storage URL: %v", err)
		}
		serviceURL = serviceURL.JoinPath(config.StorageAccountName)
	} else {
		// Use the default Azure Storage URL format
		serviceURL, err = url.Parse(fmt.Sprintf("https://%s.blob.core.windows.net/", config.StorageAccountName))
		if err != nil {
			return nil, fmt.Errorf("failed to parse service URL: %v", err)
		}
	}

	service := azblob.NewServiceURL(*serviceURL, pipeline)

	return &StorageManager{
		ServiceURL:          &service,
		SharedKeyCredential: credential,
	}, nil
}

// CreateAgentContainer creates a new container for agent communication.
// Returns the container ID and connection string that should be provided to the agent.
func (sm *StorageManager) CreateAgentContainer(expiry time.Duration) (string, string, error) {
	// Generate a unique ID for the container
	containerID := uuid.New().String()
	containerURL := sm.ServiceURL.NewContainerURL(containerID)

	ctx := context.Background()

	// Create the container with private access level
	_, err := containerURL.Create(ctx, azblob.Metadata{}, azblob.PublicAccessNone)
	if err != nil {
		return "", "", fmt.Errorf("failed to create container: %v", err)
	}

	// Initialize the required blobs
	blobNames := []string{InfoBlobName, RequestBlobName, ResponseBlobName}
	for _, blobName := range blobNames {
		blobURL := containerURL.NewBlockBlobURL(blobName)

		// Create an empty blob - it will be populated later by the agent or proxy
		_, err := blobURL.Upload(
			ctx,
			strings.NewReader(""), // Empty content initially
			azblob.BlobHTTPHeaders{
				ContentType: "application/octet-stream",
			},
			azblob.Metadata{
				"created": time.Now().UTC().Format(time.RFC3339),
			},
			azblob.BlobAccessConditions{},
			azblob.DefaultAccessTier,
			azblob.BlobTagsMap{},               // No initial tags
			azblob.ClientProvidedKeyOptions{},  // No client-provided encryption
			azblob.ImmutabilityPolicyOptions{}, // No immutability policy
		)

		if err != nil {
			// If blob creation fails, attempt to clean up the container
			if _, delErr := containerURL.Delete(ctx, azblob.ContainerAccessConditions{}); delErr != nil {
				return "", "", fmt.Errorf("failed to delete container after blob creation failed: %v", delErr)
			}
			return "", "", fmt.Errorf("failed to create %s blob: %v", blobName, err)
		}
	}

	// Generate a SAS token for the container
	sasToken, err := sm.GenerateSASToken(containerID, expiry)
	if err != nil {
		// If SAS token generation fails, clean up the container
		if _, delErr := containerURL.Delete(ctx, azblob.ContainerAccessConditions{}); delErr != nil {
			return "", "", fmt.Errorf("failed to delete container after SAS token generation failed")
		}
		return "", "", fmt.Errorf("failed to generate SAS token")
	}

	connectionString, _ := url.Parse(storageManager.ServiceURL.String())
	connectionString = connectionString.JoinPath(containerID)
	connString := connectionString.String() + "?" + sasToken

	return containerID, connString, nil
}

// GenerateSASToken creates a Shared Access Signature token for container access.
// The token provides limited-time read/write access to specific container resources.
func (sm *StorageManager) GenerateSASToken(containerName string, expiry time.Duration) (string, error) {
	// Start time is 5 minutes before now to avoid clock skew issues
	startTime := time.Now().UTC().Add(-5 * time.Minute)

	// Set expiry time (default 7 days)
	expiryTime := time.Now().UTC().Add(expiry)

	// Define the permissions for the SAS token
	permissions := azblob.ContainerSASPermissions{
		Read:  true,
		Write: true,
	}

	// Generate the SAS signature
	sasQueryParams, err := azblob.BlobSASSignatureValues{
		Protocol:      azblob.SASProtocolHTTPSandHTTP,
		StartTime:     startTime,
		ExpiryTime:    expiryTime,
		ContainerName: containerName,
		Permissions:   permissions.String(),
	}.NewSASQueryParameters(sm.SharedKeyCredential)

	if err != nil {
		return "", fmt.Errorf("failed to create SAS query parameters: %v", err)
	}

	// Convert the SAS query parameters to a string
	sasToken := sasQueryParams.Encode()
	return sasToken, nil
}

// ListAgentContainers retrieves information about all agent containers.
// It fetches container metadata and agent information, sorted by creation time.
func (sm *StorageManager) ListAgentContainers(ctx context.Context) ([]ContainerInfo, error) {
	var containers []ContainerInfo

	// List all containers in the storage account
	for marker := (azblob.Marker{}); marker.NotDone(); {
		// Get a segment of containers (up to 100 at a time)
		listResponse, err := sm.ServiceURL.ListContainersSegment(ctx, marker, azblob.ListContainersSegmentOptions{
			Prefix:     "",
			MaxResults: 0,
		})

		if err != nil {
			return nil, fmt.Errorf("failed to list containers: %v", err)
		}

		// Update marker for next iteration
		marker = listResponse.NextMarker

		// Process each container
		for _, containerItem := range listResponse.ContainerItems {
			// Create container URL for accessing blobs
			containerURL := sm.ServiceURL.NewContainerURL(containerItem.Name)

			// Try to get the info blob
			blobURL := containerURL.NewBlockBlobURL(InfoBlobName)
			downloadResponse, err := blobURL.Download(ctx, 0, azblob.CountToEnd, azblob.BlobAccessConditions{}, false, azblob.ClientProvidedKeyOptions{})

			// Skip containers that don't have our expected structure
			if err != nil {
				continue
			}

			// Read the info blob content
			bodyReader := downloadResponse.Body(azblob.RetryReaderOptions{MaxRetryRequests: 3})
			agentInfo, err := io.ReadAll(bodyReader)
			bodyReader.Close()
			if err != nil {
				log.Warn().Err(err).Str("container", containerItem.Name).Msg("Failed to read info blob")
				continue
			}
			agentInfo = protocol.Xor(agentInfo, InfoKey)

			// Get last activity from response blob
			responseBlob := containerURL.NewBlockBlobURL(ResponseBlobName)
			responseProps, err := responseBlob.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})

			// Get the last modified time, defaulting to container creation time if not available
			var lastActivity time.Time
			if err != nil {
				lastActivity = containerItem.Properties.LastModified
			} else {
				lastActivity = responseProps.LastModified()
			}

			// Check if the container has an active proxy
			var proxyPort string
			if value, running := runningProxies.Load(containerItem.Name); running {
				// Try to get the port from the server object
				if server, ok := value.(*proxy.ProxyServer); ok && server.Listener != nil {
					_, portStr, err := net.SplitHostPort(server.Listener.Addr().String())
					if err == nil {
						proxyPort = portStr
					}
				}
			}

			// Add the container to our list
			containers = append(containers, ContainerInfo{
				ID:           containerItem.Name,
				AgentInfo:    string(agentInfo),
				ProxyPort:    proxyPort,
				CreatedAt:    containerItem.Properties.LastModified,
				LastActivity: lastActivity,
			})
		}
	}

	return containers, nil
}

// RenderAgentTable formats container information into a human-readable table.
// The table includes container ID, agent info, proxy port, and timing information.
func RenderAgentTable(containers []ContainerInfo) string {
	t := table.NewWriter()
	t.SetStyle(table.StyleRounded)

	// Set up headers
	t.AppendHeader(table.Row{
		"Container ID",
		"Agent info",
		"Proxy port",
		"First seen",
		"Last seen",
	})

	// Add rows for each container
	for _, c := range containers {
		// Add the container information as a row
		t.AppendRow(table.Row{
			c.ID,
			c.AgentInfo,
			c.ProxyPort,
			c.CreatedAt.Format("2006-01-02 15:04:05"),
			c.LastActivity.Format("2006-01-02 15:04:05"),
		})
	}

	// Configure column options for better readability
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1}, // Container ID
		{Number: 2}, // Agent Info
		{Number: 3}, // Proxy port
		{Number: 4}, // Created At
		{Number: 5}, // Last Activity
	})

	return t.Render()
}

// DeleteAgentContainer removes a container and its associated blobs.
// This terminates the connection with the remote agent.
func (sm *StorageManager) DeleteAgentContainer(ctx context.Context, containerID string) error {

	// Stop any running proxy for this container
	if server, running := runningProxies.Load(containerID); running {
		if proxyServer, ok := server.(*proxy.ProxyServer); ok {
			proxyServer.Stop()
		}
		runningProxies.Delete(containerID)
	}

	// Create URL for the container we want to delete
	containerURL := sm.ServiceURL.NewContainerURL(containerID)

	// Delete the container and all its contents
	_, err := containerURL.Delete(ctx, azblob.ContainerAccessConditions{})
	if err != nil {
		return fmt.Errorf("failed to delete container")
	}

	return nil
}

// ValidateAgent checks if an agent container exists and is properly configured.
// Returns error if the container is missing.
func (sm *StorageManager) ValidateAgent(ctx context.Context, containerID string) error {
	containerURL := sm.ServiceURL.NewContainerURL(containerID)
	blobURL := containerURL.NewBlockBlobURL(InfoBlobName)

	// Try to get the info blob to verify this is a valid agent container
	_, err := blobURL.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})
	if err != nil {
		if serr, ok := err.(azblob.StorageError); ok {
			if serr.ServiceCode() == azblob.ServiceCodeContainerNotFound {
				return fmt.Errorf("agent container %s does not exist", containerID)
			}
		}
		return fmt.Errorf("invalid agent container %s: %v", containerID, err)
	}

	return nil
}

// GetSelectedAgentInfo retrieves the metadata for the currently selected agent.
// Returns error if no agent is selected or the agent information is unavailable.
func (sm *StorageManager) GetSelectedAgentInfo(ctx context.Context) (string, error) {
	if selectedAgent == "" {
		return "", fmt.Errorf("no agent selected. Use 'agent use <container-id>' first")
	}

	containerURL := sm.ServiceURL.NewContainerURL(selectedAgent)
	blobURL := containerURL.NewBlockBlobURL(InfoBlobName)

	// Download the info blob
	response, err := blobURL.Download(ctx, 0, azblob.CountToEnd, azblob.BlobAccessConditions{}, false, azblob.ClientProvidedKeyOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get agent info: %v", err)
	}

	// Read the agent info
	agentInfo, err := io.ReadAll(response.Body(azblob.RetryReaderOptions{MaxRetryRequests: 3}))
	if err != nil {
		return "", fmt.Errorf("failed to read agent info: %v", err)
	}
	agentInfo = protocol.Xor(agentInfo, InfoKey)

	return string(agentInfo), nil
}

// AddCommands registers all CLI commands with the application.
// This includes commands for agent management, proxy control, and configuration.
func AddCommands(app *grumble.App) {
	// Command to create a new agent
	app.AddCommand(&grumble.Command{
		Name:    "create",
		Aliases: []string{"new"},
		Help:    "create a new agent container and generate its connection string",
		Flags: func(f *grumble.Flags) {
			f.Duration("d", "duration", 7*24*time.Hour, "duration for the SAS token. by default the token will be valid for 7 days")
		},
		Run: func(c *grumble.Context) error {
			expiry := c.Flags.Duration("duration")
			containerID, connString, err := storageManager.CreateAgentContainer(expiry)
			if err != nil {
				log.Error().Err(err).Msg("Failed to create agent container")
				return nil
			}
			log.Info().Str("container_id", containerID).Msg("Agent container created successfully")
			log.Info().Str("connection_string", base64.RawStdEncoding.EncodeToString([]byte(connString))).Msg("Connection string generated")
			return nil
		},
	})
	// Command to list existing agents
	app.AddCommand(&grumble.Command{
		Name:    "list",
		Aliases: []string{"ls"},
		Help:    "list all existing agent containers",
		Run: func(c *grumble.Context) error {
			ctx := context.Background()

			// Retrieve all containers
			containers, err := storageManager.ListAgentContainers(ctx)
			if err != nil {
				log.Error().Err(err).Msg("Failed to list containers")
				return nil
			}

			// Display message if no containers found
			if len(containers) == 0 {
				log.Info().Msg("No agent containers found")
				return nil
			}

			// Display the container table
			c.App.Println(RenderAgentTable(containers))
			return nil
		},
	})
	// Command to delete an agent
	app.AddCommand(&grumble.Command{
		Name:    "delete",
		Aliases: []string{"rm"},
		Help:    "delete an existing agent container",
		Args: func(a *grumble.Args) {
			a.StringList("containers-id", "ID of the containers to delete")
		},
		Completer: CompleteAgents,
		Run: func(c *grumble.Context) error {
			containerIDs := c.Args.StringList("containers-id")
			if len(containerIDs) == 0 {
				containerIDs = append(containerIDs, selectedAgent)
			}

			for _, containerID := range containerIDs {
				// Ask for confirmation before deletion
				log.Info().Str("container_id", containerID).Msg("Are you sure you want to delete container? [y/N]")
				var response string
				fmt.Scanln(&response)

				if strings.ToLower(response) != "y" {
					log.Info().Msg("Deletion cancelled")
					return nil
				}

				// Proceed with deletion
				ctx := context.Background()
				if err := storageManager.DeleteAgentContainer(ctx, containerID); err != nil {
					log.Error().Err(err).Str("container_id", containerID).Msg("Failed to delete container")
					return nil
				}

				if selectedAgent == containerID {
					selectedAgent = ""
					c.App.SetPrompt("proxyblob » ")
				}

				log.Info().Str("container_id", containerID).Msg("Container deleted successfully")
			}
			return nil
		},
	})
	// Command to select an agent
	app.AddCommand(&grumble.Command{
		Name:    "select",
		Aliases: []string{"use"},
		Help:    "select an agent for subsequent commands",
		Args: func(a *grumble.Args) {
			a.String("container-id", "ID of the container to select")
		},
		Completer: CompleteAgents,
		Run: func(c *grumble.Context) error {
			ctx := context.Background()
			containerID := c.Args.String("container-id")

			// Validate the agent exists
			if err := storageManager.ValidateAgent(ctx, containerID); err != nil {
				log.Error().Err(err).Msg("Failed to validate agent")
				return nil
			}

			// Store the selected agent
			selectedAgent = containerID

			// Get and display agent info
			agentInfo, err := storageManager.GetSelectedAgentInfo(ctx)
			if err != nil {
				log.Error().Err(err).Msg("Failed to get agent info")
				return nil
			}
			if agentInfo == "" {
				agentInfo = "unknown@host"
			}

			log.Info().Str("agent", agentInfo).Msg("Agent selected")
			c.App.SetPrompt(agentInfo + " » ")

			return nil
		},
	})
	// Command to start the proxy server over the current selected agent
	app.AddCommand(&grumble.Command{
		Name:    "start",
		Aliases: []string{"proxy"},
		Help:    "start SOCKS proxy server",
		Flags: func(f *grumble.Flags) {
			f.String("l", "listen", "127.0.0.1:1080", "listen address for SOCKS server")
		},
		Run: func(c *grumble.Context) error {
			if selectedAgent == "" {
				log.Warn().Msg("No agent selected. Use 'select <container-id>' first")
				return nil
			}

			if _, exists := runningProxies.Load(selectedAgent); exists {
				log.Warn().Msg("Proxy already running for this agent")
				return nil
			}

			// Verify the container still exists before starting a proxy
			ctx := context.Background()

			// Check if the container exists
			if err := storageManager.ValidateAgent(ctx, selectedAgent); err != nil {
				log.Error().Err(err).Msg("Cannot start proxy")
				return nil
			}

			containerURL := storageManager.ServiceURL.NewContainerURL(selectedAgent)
			transport := transport.NewBlobTransport(
				containerURL.NewBlockBlobURL(ResponseBlobName),
				containerURL.NewBlockBlobURL(RequestBlobName),
			)

			server := proxy.NewProxyServer(ctx, transport)
			listenAddr := c.Flags.String("listen")

			runningProxies.Store(selectedAgent, server)
			server.Start(listenAddr)

			// Log the port info for user feedback
			if server.Listener != nil {
				_, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
				// Get agent info for notification
				agentInfo, err := storageManager.GetSelectedAgentInfo(context.Background())
				if err != nil || agentInfo == "" {
					agentInfo = selectedAgent // Fallback to container ID if we can't get agent info
				}

				log.Info().Str("agent", agentInfo).Str("port", portStr).Msg("Proxy started successfully")
			}

			return nil
		},
	})
	// Command to stop the proxy server running the current selected agent
	app.AddCommand(&grumble.Command{
		Name: "stop",
		Help: "stop running proxy for the selected agent",
		Run: func(c *grumble.Context) error {
			if selectedAgent == "" {
				log.Warn().Msg("No agent selected. Use 'select <container-id>' first")
				return nil
			}

			// Retrieve and remove the value from the map in one atomic operation
			value, exists := runningProxies.LoadAndDelete(selectedAgent)
			if !exists {
				log.Warn().Msg("No proxy running for this agent")
				return nil
			}

			// Try to stop the proxy gracefully
			server, _ := value.(*proxy.ProxyServer)
			server.Stop()

			// Get agent info for notification
			agentInfo, err := storageManager.GetSelectedAgentInfo(context.Background())
			if err != nil || agentInfo == "" {
				agentInfo = selectedAgent // Fallback to container ID if we can't get agent info
			}

			log.Info().Str("agent", agentInfo).Msg("Proxy stopped")

			return nil
		},
	})
}

// CompleteAgents provides tab completion for agent IDs.
// Returns a list of available agent container IDs.
func CompleteAgents(_ string, _ []string) []string {
	containers, err := storageManager.ListAgentContainers(context.Background())
	if err != nil {
		return []string{} // Return empty slice on error
	}

	var completions []string
	for _, container := range containers {
		completions = append(completions, container.ID)
	}
	return completions
}

// -----------------------------------------------------------------------------
// Main Application Entry
// -----------------------------------------------------------------------------

// main is the entry point for the application.
// It sets up the CLI, configuration, and command handlers.
func main() {
	// Set up logging
	configureLogging()

	// Configure and create the CLI app
	app := setupCLI()

	// Add all command handlers
	AddCommands(app)

	// Run the application and handle any errors
	if err := app.Run(); err != nil {
		log.Fatal().Msg(err.Error())
	}
}

// configureLogging sets up zerolog with appropriate formatting and level.
func configureLogging() {
	// Configure zerolog with a pretty console writer for interactive use
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "15:04:05",
	})

	// Set reasonable default log level
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
}

// setupCLI initializes the command-line interface with basic configuration.
// Returns a configured grumble App instance.
func setupCLI() *grumble.App {
	// Determine history file location
	var histFile string
	home, err := os.UserHomeDir()
	if err != nil {
		histFile = ".proxyblob" // current working directory
	} else {
		histFile = filepath.Join(home, ".proxyblob") // home directory
	}

	// Create and configure the CLI app
	app := grumble.New(&grumble.Config{
		Name:        "proxyblob",
		HistoryFile: histFile,
		Flags: func(f *grumble.Flags) {
			f.String("c", "config", "config.json", "path to configuration file")
		},
	})

	// Set up our ASCII art banner
	app.SetPrintASCIILogo(func(a *grumble.App) {
		fmt.Print(banner)
	})

	// Initialize configuration when the app starts
	app.OnInit(func(a *grumble.App, flags grumble.FlagMap) error {
		// Load configuration from file
		var err error
		config, err = LoadConfig(flags.String("config"))
		if err != nil {
			return fmt.Errorf("failed to load configuration: %v", err)
		}

		// Validate the configuration
		if err := config.Validate(); err != nil {
			return fmt.Errorf("invalid configuration: %v", err)
		}

		// Initialize the storage manager
		storageManager, err = NewStorageManager(config)
		if err != nil {
			return fmt.Errorf("failed to initialize storage manager: %v", err)
		}

		return nil
	})

	return app
}
