// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "data.". The ledger stores each as "audit." + the kind.
const (
	DataDeletionCanceled   = "data.deletion_canceled"
	DataDeletionRecordRead = "data.deletion_record_read"
	DataDeletionRequested  = "data.deletion_requested"
	DataExportDownloaded   = "data.export_downloaded"
	DataExportReady        = "data.export_ready"
	DataExportRequested    = "data.export_requested"
)
