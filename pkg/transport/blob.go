// Package transport provides interfaces and implementations for communication
// between proxy components. It abstracts the underlying transport mechanism
// and ensures reliable data transfer with proper error handling.
package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	"github.com/Azure/azure-storage-blob-go/azblob"
)

// Retry configuration for blob operations.
const (
	InitialRetryDelay = 50 * time.Millisecond // Starting delay between retries
	MaxRetryDelay     = 3 * time.Second       // Maximum delay between retries
	BackoffFactor     = 1.5                   // Multiplier for exponential backoff
)

// BlobTransport implements the Transport interface using Azure Blob Storage.
// It uses separate blobs for reading and writing to provide bidirectional
// communication. All operations are retried with exponential backoff.
type BlobTransport struct {
	readBlob  azblob.BlockBlobURL // Blob for receiving data
	writeBlob azblob.BlockBlobURL // Blob for sending data
}

// NewBlobTransport creates a transport that uses the provided blobs for
// bidirectional communication. The readBlob is used for receiving data,
// and the writeBlob is used for sending data.
func NewBlobTransport(readBlob, writeBlob azblob.BlockBlobURL) *BlobTransport {
	return &BlobTransport{
		readBlob:  readBlob,
		writeBlob: writeBlob,
	}
}

// Send writes data to the write blob. It blocks until the data is written
// or the context is canceled. Returns an error code indicating success or
// specific failure reason.
func (t *BlobTransport) Send(ctx context.Context, data []byte) byte {
	return WriteBlob(ctx, t.writeBlob, data)
}

// Receive reads and clears data from the read blob. It blocks until data
// is available or the context is canceled. Returns the read data and an
// error code indicating success or failure reason.
func (t *BlobTransport) Receive(ctx context.Context) ([]byte, byte) {
	return WaitForData(ctx, t.readBlob)
}

// IsClosed reports whether the transport is permanently closed.
func (t *BlobTransport) IsClosed(errCode byte) bool {
	return errCode == ErrTransportClosed
}

// WriteBlob attempts to write data to a blob with retry and exponential backoff.
// The operation is retried until successful or the context is canceled.
// Returns an error code indicating success or specific failure reason.
func WriteBlob(ctx context.Context, blobURL azblob.BlockBlobURL, data []byte) byte {
	retryDelay := InitialRetryDelay

	// Try the operation with unlimited retries
	for {
		// Check if blob is empty
		isEmpty, errCode := IsBlobEmpty(ctx, blobURL)
		if errCode != ErrNone {
			return errCode
		}

		if !isEmpty {
			// If the blob isn't empty, wait before retrying
			retryDelay, errCode = WaitDelay(ctx, retryDelay)
			if errCode != ErrNone {
				return errCode
			}
			continue
		}

		// Reset delay when we find empty blob
		retryDelay = InitialRetryDelay

		// Upload data to the blob
		_, err := blobURL.Upload(
			ctx,
			bytes.NewReader(data),
			azblob.BlobHTTPHeaders{ContentType: "application/octet-stream"},
			azblob.Metadata{},
			azblob.BlobAccessConditions{},
			azblob.DefaultAccessTier,
			nil,
			azblob.ClientProvidedKeyOptions{},
			azblob.ImmutabilityPolicyOptions{},
		)

		if err != nil {
			// If upload fails, check context and retry
			if ctx.Err() != nil {
				return ErrContextCanceled
			}

			// Wait before retrying with exponential backoff
			retryDelay, errCode = WaitDelay(ctx, retryDelay)
			if errCode != ErrNone {
				return errCode
			}
			continue
		}

		// Success
		return ErrNone
	}
}

// WaitForData polls a blob until data is available, then reads and clears it.
// The operation is retried with exponential backoff until data is found or
// the context is canceled. Returns the read data and an error code indicating
// success or failure reason.
func WaitForData(ctx context.Context, blobURL azblob.BlockBlobURL) ([]byte, byte) {
	var data []byte
	retryDelay := InitialRetryDelay

	for {
		// Check for cancellation
		if ctx.Err() != nil {
			return nil, ErrContextCanceled
		}

		// Poll until the blob contains data
		isEmpty, errCode := IsBlobEmpty(ctx, blobURL)
		if errCode != ErrNone {
			return nil, errCode
		}

		if isEmpty {
			// If empty, wait before checking again with exponential backoff
			retryDelay, errCode = WaitDelay(ctx, retryDelay)
			if errCode != ErrNone {
				return nil, errCode
			}
			continue
		}

		// Reset delay when we find data
		retryDelay = InitialRetryDelay

		// Found data, download the blob content
		response, err := blobURL.Download(ctx, 0, azblob.CountToEnd, azblob.BlobAccessConditions{}, false, azblob.ClientProvidedKeyOptions{})
		if err != nil {
			return nil, BlobError(err)
		}

		bodyReader := response.Body(azblob.RetryReaderOptions{MaxRetryRequests: 3})
		defer bodyReader.Close()

		// Read the data
		data, err = io.ReadAll(bodyReader)
		if err != nil {
			return nil, ErrTransportError
		}

		// Clear the blob - no retries here
		errCode = ClearBlob(ctx, blobURL)
		if errCode != ErrNone {
			return nil, errCode
		}

		return data, ErrNone
	}
}

// IsBlobEmpty checks if a blob is empty by retrieving its properties.
// Returns true if the blob has zero content length, and an error code
// indicating success or failure reason.
func IsBlobEmpty(ctx context.Context, blobURL azblob.BlockBlobURL) (bool, byte) {
	// Check for cancelation
	props, err := blobURL.GetProperties(ctx, azblob.BlobAccessConditions{}, azblob.ClientProvidedKeyOptions{})
	if err != nil {
		return false, BlobError(err)
	}

	return props.ContentLength() == 0, ErrNone
}

// ClearBlob empties a blob's contents by uploading an empty byte slice.
// The operation is retried with exponential backoff until successful or
// the context is canceled. Returns an error code indicating success or
// specific failure reason.
func ClearBlob(ctx context.Context, blobURL azblob.BlockBlobURL) byte {
	var errCode byte
	retryDelay := InitialRetryDelay

	// Try the operation with unlimited retries
	for {
		_, err := blobURL.Upload(
			ctx,
			bytes.NewReader([]byte{}),
			azblob.BlobHTTPHeaders{ContentType: "application/octet-stream"},
			azblob.Metadata{},
			azblob.BlobAccessConditions{},
			azblob.DefaultAccessTier,
			nil,
			azblob.ClientProvidedKeyOptions{},
			azblob.ImmutabilityPolicyOptions{},
		)

		if err == nil {
			// Success, no error
			return ErrNone
		}

		// Wait before retrying with exponential backoff
		retryDelay, errCode = WaitDelay(ctx, retryDelay)
		if errCode != ErrNone {
			return errCode
		}
	}
}

// BlobError maps Azure Blob Storage errors to transport error codes.
// It handles common error cases like container not found, network issues,
// and authentication failures.
func BlobError(err error) byte {
	// Quick check for nil
	if err == nil {
		return ErrNone
	}

	// Check for context cancellation
	if errors.Is(err, context.Canceled) {
		return ErrContextCanceled
	}

	// Check for container-related errors (indicating transport is closed)
	if storageErr, ok := err.(azblob.StorageError); ok {
		serviceCode := storageErr.ServiceCode()
		if serviceCode == azblob.ServiceCodeContainerNotFound ||
			serviceCode == azblob.ServiceCodeContainerBeingDeleted ||
			serviceCode == azblob.ServiceCodeAccountBeingCreated {
			return ErrTransportClosed
		}
	}

	// All other errors are treated as general transport errors
	return ErrTransportError
}

// WaitDelay implements exponential backoff for retry operations.
// It sleeps for the current delay and returns the next delay duration,
// which is the current delay multiplied by BackoffFactor, capped at
// MaxRetryDelay. Returns an error code if the context is canceled.
func WaitDelay(ctx context.Context, retryDelay time.Duration) (time.Duration, byte) {
	select {
	case <-ctx.Done():
		return 0, ErrContextCanceled
	case <-time.After(retryDelay):
		retryDelay = time.Duration(float64(retryDelay) * BackoffFactor)
		if retryDelay > MaxRetryDelay {
			retryDelay = MaxRetryDelay
		}
		return retryDelay, ErrNone
	}
}
