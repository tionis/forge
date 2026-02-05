package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Constants as per specification
const (
	XattrHashKey  = "user.checksum.sha256"
	XattrMtimeKey = "user.checksum.mtime"
	BufferSize    = 128 * 1024 // 128KB is generally optimal for sequential reads
)

// Statistics for the run
var (
	filesChecked uint64
	filesHashed  uint64
	filesSkipped uint64
	errors       uint64
)

// Buffer pool to reduce GC pressure
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, BufferSize)
		return &b
	},
}

func main() {
	// Parse CLI args
	workers := flag.Int("w", runtime.NumCPU(), "Number of parallel workers")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	root := flag.Arg(0)
	if root == "" {
		root = "."
	}

	start := time.Now()
	log.Printf("Starting hash tagger on: %s (Workers: %d)", root, *workers)

	// Worker Pool Channels
	jobs := make(chan string, 100)
	var wg sync.WaitGroup

	// Start Workers
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				processFile(path, *verbose)
			}
		}()
	}

	// Walk filesystem
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			log.Printf("Error accessing path %q: %v", path, err)
			return nil
		}
		// Skip directories and non-regular files
		if !d.Type().IsRegular() {
			return nil
		}
		// Skip .git directory
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}

		jobs <- path
		return nil
	})

	close(jobs)
	wg.Wait()

	if err != nil {
		log.Printf("Walk error: %v", err)
	}

	duration := time.Since(start)
	log.Printf("\nDone in %s.", duration)
	log.Printf("Checked: %d | Hashed (New/Changed): %d | Skipped (Cache Hit): %d | Errors: %d",
		atomic.LoadUint64(&filesChecked),
		atomic.LoadUint64(&filesHashed),
		atomic.LoadUint64(&filesSkipped),
		atomic.LoadUint64(&errors),
	)
}

func processFile(path string, verbose bool) {
	atomic.AddUint64(&filesChecked, 1)

	// 1. Stat the file to get current mtime
	// We use syscall.Stat directly to get the raw timespec for efficiency if needed,
	// but os.Stat is portable and sufficient for "seconds" precision.
	info, err := os.Stat(path)
	if err != nil {
		handleError(path, err, verbose)
		return
	}
	
	currentMtime := info.ModTime().Unix()

	// 2. CHECK CACHE (The Fast Path)
	// If we can read the xattrs and the mtime matches, we stop here.
	if isCacheValid(path, currentMtime) {
		atomic.AddUint64(&filesSkipped, 1)
		if verbose {
			fmt.Printf("[SKIP] %s\n", path)
		}
		return
	}

	// 3. CACHE MISS - Compute Hash
	// Acquire buffer from pool
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	// Open file
	f, err := os.Open(path)
	if err != nil {
		handleError(path, err, verbose)
		return
	}
	// We cannot defer f.Close() blindly if we want to check mtime AFTER close, 
	// but we'll Stat the file handle or path again. 
	// To be safe and simple: close immediately after hash.

	hasher := sha256.New()
	if _, err := io.CopyBuffer(hasher, f, buf); err != nil {
		f.Close()
		handleError(path, err, verbose)
		return
	}
	f.Close() // Close explicitly before second stat

	computedHash := hex.EncodeToString(hasher.Sum(nil))

	// 4. ATOMICITY CHECK
	// Verify file wasn't modified during read
	infoPost, err := os.Stat(path)
	if err != nil {
		handleError(path, err, verbose)
		return
	}

	if info.ModTime() != infoPost.ModTime() {
		if verbose {
			log.Printf("[WARN] File modified during read, skipping: %s", path)
		}
		return
	}

	// 5. WRITE XATTRS
	if err := writeXattrs(path, computedHash, currentMtime); err != nil {
		handleError(path, err, verbose)
		return
	}

	atomic.AddUint64(&filesHashed, 1)
	if verbose {
		fmt.Printf("[HASH] %s\n", path)
	}
}

// isCacheValid checks if the file has a valid mtime and hash attribute
func isCacheValid(path string, currentMtime int64) bool {
	// Read Mtime Attribute
	mtimeData, err := getXattr(path, XattrMtimeKey)
	if err != nil {
		return false // Attribute doesn't exist or FS error
	}

	// Parse stored mtime
	cachedMtime, err := strconv.ParseInt(string(mtimeData), 10, 64)
	if err != nil {
		return false // Corrupt data
	}

	if cachedMtime != currentMtime {
		return false // Stale
	}

	// Check if hash attribute exists (sanity check)
	_, err = getXattr(path, XattrHashKey)
	return err == nil
}

// writeXattrs sets the hash and mtime attributes
func writeXattrs(path string, hash string, mtime int64) error {
	mtimeStr := strconv.FormatInt(mtime, 10)

	// We ignore "operation not supported" errors silently for non-compatible FS
	if err := setXattr(path, XattrHashKey, []byte(hash)); err != nil {
		return err
	}
	if err := setXattr(path, XattrMtimeKey, []byte(mtimeStr)); err != nil {
		return err
	}
	return nil
}

func handleError(path string, err error, verbose bool) {
	atomic.AddUint64(&errors, 1)
	// Ignore permission denied or operation not supported to reduce noise in non-verbose mode
	if verbose {
		log.Printf("Error on %s: %v", path, err)
	}
}

// --- Low Level Syscall Wrappers (Linux Specific) ---

func getXattr(path string, name string) ([]byte, error) {
	// Start with a reasonable buffer size for xattr
	dest := make([]byte, 128)
	sz, err := syscall.Getxattr(path, name, dest)
	if err != nil {
		return nil, err
	}
	return dest[:sz], nil
}

func setXattr(path string, name string, data []byte) error {
	return syscall.Setxattr(path, name, data, 0)
}
