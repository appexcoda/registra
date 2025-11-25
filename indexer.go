package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	writeQueueSize      = 1000
	batchInsertSize     = 100
	batchDeleteSize     = 100
	batchFlushInterval  = 500 * time.Millisecond
	progressLogInterval = 100
	scanInterval        = 1 * time.Minute
)

type writeRequest struct {
	metadata *FileMetadata
	isDelete bool
	path     string
}

type Indexer struct {
	db           *DB
	rootPaths    []string
	absRootPaths []string
	concurrency  int
	writeQueue   chan writeRequest
	writerDone   chan struct{}
	scanning     atomic.Bool

	metrics struct {
		filesIndexed   atomic.Int64
		filesDeleted   atomic.Int64
		indexingErrors atomic.Int64
		batchesWritten atomic.Int64
	}
}

func NewIndexer(db *DB, rootPaths []string, concurrency int) *Indexer {
	absRootPaths := make([]string, 0, len(rootPaths))
	for _, rp := range rootPaths {
		if abs, err := filepath.Abs(rp); err == nil {
			absRootPaths = append(absRootPaths, abs)
		}
	}

	idx := &Indexer{
		db:           db,
		rootPaths:    rootPaths,
		absRootPaths: absRootPaths,
		concurrency:  concurrency,
		writeQueue:   make(chan writeRequest, writeQueueSize),
		writerDone:   make(chan struct{}),
	}

	go idx.writerWorker()
	return idx
}

func (idx *Indexer) writerWorker() {
	defer close(idx.writerDone)

	insertBatch := make([]*FileMetadata, 0, batchInsertSize)
	deleteBatch := make([]string, 0, batchDeleteSize)
	ticker := time.NewTicker(batchFlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(insertBatch) > 0 {
			count := len(insertBatch)
			if err := idx.db.InsertFileBatch(insertBatch); err != nil {
				AppLogger.Error("Batch insert failed (%d files): %v", count, err)
				idx.metrics.indexingErrors.Add(int64(count))
			} else {
				idx.metrics.filesIndexed.Add(int64(count))
				idx.metrics.batchesWritten.Add(1)
			}
			insertBatch = insertBatch[:0]
		}

		if len(deleteBatch) > 0 {
			count := len(deleteBatch)
			if err := idx.db.DeleteFileBatch(deleteBatch); err != nil {
				AppLogger.Error("Batch delete failed (%d files): %v", count, err)
			} else {
				idx.metrics.filesDeleted.Add(int64(count))
				idx.metrics.batchesWritten.Add(1)
			}
			deleteBatch = deleteBatch[:0]
		}
	}

	for {
		select {
		case req, ok := <-idx.writeQueue:
			if !ok {
				flush()
				return
			}

			if req.isDelete {
				deleteBatch = append(deleteBatch, req.path)
				if len(deleteBatch) >= batchDeleteSize {
					flush()
				}
			} else {
				insertBatch = append(insertBatch, req.metadata)
				if len(insertBatch) >= batchInsertSize {
					flush()
				}
			}

		case <-ticker.C:
			flush()
		}
	}
}

func (idx *Indexer) InitialScan() error {
	if !idx.scanning.CompareAndSwap(false, true) {
		AppLogger.Warn("Scan already in progress")
		return nil
	}
	defer idx.scanning.Store(false)

	AppLogger.Info("Starting scan of %d directories", len(idx.rootPaths))

	dbFiles, err := idx.db.GetAllFiles()
	if err != nil {
		return fmt.Errorf("failed to get DB files: %v", err)
	}

	dbMap := make(map[string]*FileMetadata)
	for _, f := range dbFiles {
		dbMap[f.FilePath] = f
	}

	var fsFiles []string
	var mu sync.Mutex

	for _, rootPath := range idx.rootPaths {
		err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			if d.Name()[0] == '.' {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}

			if !d.IsDir() && isSupportedFile(path) {
				mu.Lock()
				fsFiles = append(fsFiles, path)
				mu.Unlock()
			}

			return nil
		})

		if err != nil {
			AppLogger.Error("Error scanning %s: %v", rootPath, err)
		}
	}

	fsMap := make(map[string]bool)
	var toProcess []string

	for _, path := range fsFiles {
		fsMap[path] = true

		dbFile, exists := dbMap[path]
		if !exists {
			toProcess = append(toProcess, path)
			continue
		}

		info, err := os.Stat(path)
		if err == nil && info.ModTime().After(dbFile.ModifiedAt) {
			toProcess = append(toProcess, path)
		}
	}

	var toDelete []string
	for path := range dbMap {
		if !fsMap[path] {
			toDelete = append(toDelete, path)
		}
	}

	if len(toDelete) > 0 {
		AppLogger.Info("Removing %d deleted files from index", len(toDelete))
		for _, path := range toDelete {
			idx.writeQueue <- writeRequest{isDelete: true, path: path}
		}
	}

	if len(toProcess) > 0 {
		AppLogger.Info("Indexing %d new/modified files", len(toProcess))
		idx.processConcurrently(toProcess)
	}

	if len(toProcess) == 0 && len(toDelete) == 0 {
		AppLogger.Info("Scan complete: no changes")
	} else {
		AppLogger.Info("Scan complete: %d indexed, %d deleted", len(toProcess), len(toDelete))
	}

	return nil
}

func (idx *Indexer) processConcurrently(files []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, idx.concurrency)

	total := len(files)
	var processed atomic.Int32

	for _, path := range files {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			metadata, err := ExtractMetadata(p)
			if err != nil {
				idx.metrics.indexingErrors.Add(1)
				AppLogger.Error("Failed to extract metadata from %s: %v", p, err)
				return
			}

			if metadata.FileHash != "" {
				exists, existingPath, _ := idx.db.FileExistsByHash(metadata.FileHash)
				if exists && existingPath != metadata.FilePath {
					if _, err := os.Stat(existingPath); err == nil {
						AppLogger.Debug("Skipping duplicate: %s (identical to %s)", p, existingPath)
						return
					}
				}
			}

			idx.writeQueue <- writeRequest{metadata: metadata}

			count := processed.Add(1)
			if count%progressLogInterval == 0 || count == int32(total) {
				AppLogger.Info("Progress: %d/%d files", count, total)
			}
		}(path)
	}

	wg.Wait()
}

func (idx *Indexer) StartPeriodicScan() {
	go func() {
		ticker := time.NewTicker(scanInterval)
		defer ticker.Stop()

		for range ticker.C {
			if err := idx.InitialScan(); err != nil {
				AppLogger.Error("Periodic scan error: %v", err)
			}
		}
	}()

	AppLogger.Info("Periodic scan started (interval: %v)", scanInterval)
}

func (idx *Indexer) IndexFile(path string) error {
	metadata, err := ExtractMetadata(path)
	if err != nil {
		return err
	}

	if metadata.FileHash != "" {
		exists, existingPath, _ := idx.db.FileExistsByHash(metadata.FileHash)
		if exists && existingPath != metadata.FilePath {
			if _, err := os.Stat(existingPath); err == nil {
				return fmt.Errorf("%w: %s", ErrDuplicateFile, existingPath)
			}
		}
	}

	idx.writeQueue <- writeRequest{metadata: metadata}
	return nil
}

func (idx *Indexer) IsValidPath(filePath string) bool {
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		return false
	}

	for _, absRoot := range idx.absRootPaths {
		rel, err := filepath.Rel(absRoot, absFilePath)
		if err == nil && !strings.HasPrefix(rel, "..") {
			return true
		}
	}

	return false
}

func (idx *Indexer) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"queue_depth":     len(idx.writeQueue),
		"files_indexed":   idx.metrics.filesIndexed.Load(),
		"files_deleted":   idx.metrics.filesDeleted.Load(),
		"indexing_errors": idx.metrics.indexingErrors.Load(),
		"batches_written": idx.metrics.batchesWritten.Load(),
		"queue_capacity":  writeQueueSize,
	}
}

func (idx *Indexer) Close() error {
	AppLogger.Info("Closing indexer, flushing write queue...")
	close(idx.writeQueue)
	<-idx.writerDone
	AppLogger.Info("Write queue flushed")
	return nil
}

func (idx *Indexer) WaitForQueue() {
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			AppLogger.Warn("WaitForQueue timeout - queue depth: %d", len(idx.writeQueue))
			return
		case <-ticker.C:
			if len(idx.writeQueue) == 0 {
				time.Sleep(batchFlushInterval + 100*time.Millisecond)
				return
			}
		}
	}
}
