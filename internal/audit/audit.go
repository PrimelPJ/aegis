
// Verification tuning constants.
const (
	// DefaultVerifyBatchSize is the number of events to load per batch
	// during chain verification.  Larger batches use more memory but
	// reduce round trips to the store.
	DefaultVerifyBatchSize = 1000

	// MaxVerifyBatchSize caps the batch size to prevent OOM on large
	// event stores.
	MaxVerifyBatchSize = 10000

	// VerifyProgressInterval is the number of events between progress
	// log messages during long verification runs.
	VerifyProgressInterval = 50000
)
