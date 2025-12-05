package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"net/url"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

/* ======================================================
   CONFIG
====================================================== */

type Config struct {
	Listen         string `json:"listen"`
	MinioEndpoint  string `json:"minio_endpoint"`
	MinioUseSSL    bool   `json:"minio_use_ssl"`
	MinioAccessKey string `json:"minio_access_key"`
	MinioSecretKey string `json:"minio_secret_key"`
	Bucket         string `json:"bucket"`
	AESKeyB64      string `json:"aes_key_b64"`
	CallbackURL    string `json:"callback_url"` // Laravel callback
}

type CallbackPayload struct {
	BackupID     int64  `json:"backup_id"`
	Filename     string `json:"filename"`
	MinioPath    string `json:"minio_path"`
	OriginalSize int64  `json:"original_size"`
	FinalSize    int64  `json:"final_size"`
	DurationMs   int64  `json:"duration_ms"`
}

var cfg Config
var minioClient *minio.Client
var aesKey []byte

/* ======================================================
   LOAD CONFIG & INIT MINIO
====================================================== */

func loadConfig() {
	f, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("open config.json: %v", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		log.Fatalf("decode config.json: %v", err)
	}

	key, err := base64.StdEncoding.DecodeString(cfg.AESKeyB64)
	if err != nil || len(key) != 32 {
		log.Fatalf("AES key must be 32 bytes")
	}
	aesKey = key

	log.Println("[CONFIG] Loaded")
}

func initMinio() {
	var err error
	minioClient, err = minio.New(cfg.MinioEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinioAccessKey, cfg.MinioSecretKey, ""),
		Secure: cfg.MinioUseSSL,
	})
	if err != nil {
		log.Fatalf("[MINIO] init error: %v", err)
	}

	exists, err := minioClient.BucketExists(context.Background(), cfg.Bucket)
	if err != nil {
		log.Fatalf("bucket exists: %v", err)
	}
	if !exists {
		if err := minioClient.MakeBucket(context.Background(), cfg.Bucket, minio.MakeBucketOptions{}); err != nil {
			log.Fatalf("make bucket: %v", err)
		}
		log.Printf("[MINIO] Bucket %s created", cfg.Bucket)
	}

	log.Println("[MINIO] Connected.")
}

/* ======================================================
   HELPERS
====================================================== */

func writeUint64(w io.Writer, v uint64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}

func readUint64(r io.Reader) (uint64, error) {
	var buf [8]byte
	_, err := io.ReadFull(r, buf[:])
	return binary.BigEndian.Uint64(buf[:]), err
}

const LOG_INTERVAL = int64(50 * 1024 * 1024) // 50MB

/* ======================================================
   UPLOAD HANDLER (compress + encrypt + upload)
====================================================== */

func UploadHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "filename required", 400)
		return
	}

	// backup_id dari Laravel (supaya callback bisa update row yang tepat)
	backupIDStr := r.URL.Query().Get("backup_id")
	var backupID int64
	if backupIDStr != "" {
		id, err := strconv.ParseInt(backupIDStr, 10, 64)
		if err != nil {
			log.Printf("[UPLOAD] Invalid backup_id %q: %v", backupIDStr, err)
		} else {
			backupID = id
			log.Printf("[UPLOAD] Using backup_id = %d", backupID)
		}
	} else {
		log.Println("[UPLOAD] No backup_id provided (callback will have 0)")
	}

	objectName := fmt.Sprintf("backups/%s.enc", filename)

	log.Println("──────────────────────────────────────────────")
	log.Printf("[UPLOAD] Start for %s", filename)

	// ORIGINAL SIZE (best effort – untuk multipart bisa sedikit lebih besar)
	originalSize := r.ContentLength

	var fileReader io.Reader
	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "multipart/form-data") {
		log.Println("[UPLOAD] Mode: multipart/form-data")
		mr, err := r.MultipartReader()
		if err != nil {
			log.Printf("[UPLOAD] multipart read err: %v", err)
			http.Error(w, "multipart read err", 500)
			return
		}
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Printf("[UPLOAD] multipart NextPart err: %v", err)
				http.Error(w, "multipart part err", 500)
				return
			}
			if part.FormName() == "file" {
				fileReader = part
				break
			}
		}
		if fileReader == nil {
			http.Error(w, "missing file part", 400)
			return
		}
	} else {
		log.Println("[UPLOAD] Mode: raw body")
		fileReader = r.Body
	}

	pr, pw := io.Pipe()

	// 🔁 PIPELINE: fileReader → flate → AES-GCM → pw → MinIO
	go func() {
		compPr, compPw := io.Pipe()
		compWriter, _ := flate.NewWriter(compPw, flate.DefaultCompression)

		var wg sync.WaitGroup
		wg.Add(1)

		// ENCRYPTOR
		go func() {
			defer wg.Done()
			defer compPr.Close()

			block, _ := aes.NewCipher(aesKey)
			aead, _ := cipher.NewGCM(block)
			buf := make([]byte, 1024*1024)

			var encryptCount int64

			for {
				n, err := compPr.Read(buf)
				if n > 0 {
					encryptCount += int64(n)
					if encryptCount%LOG_INTERVAL < int64(len(buf)) {
						log.Printf("[ENCRYPT] %s: %.2f MB", filename, float64(encryptCount)/1024/1024)
					}

					nonce := make([]byte, aead.NonceSize())
					if _, errRand := rand.Read(nonce); errRand != nil {
						log.Printf("[ENCRYPT] Finished encrypt loop for %s", filename)
						return
					}

					ciphertext := aead.Seal(nil, nonce, buf[:n], nil)

					if _, errW := pw.Write(nonce); errW != nil {
						log.Printf("[PIPE] write nonce error: %v", errW)
						return
					}
					if err := writeUint64(pw, uint64(len(ciphertext))); err != nil {
						log.Printf("[PIPE] write len error: %v", err)
						return
					}
					if _, errW := pw.Write(ciphertext); errW != nil {
						log.Printf("[PIPE] write ciphertext error: %v", errW)
						return
					}
				}

				if err != nil {
					if err != io.EOF {
						log.Printf("[ENCRYPT] read err: %v", err)
					}
					return
				}
			}
		}()

		// COMPRESSOR: fileReader → compWriter
		buf2 := make([]byte, 1024*1024)
		var readCount int64

		for {
			n, err := fileReader.Read(buf2)
			if n > 0 {
				readCount += int64(n)
				if readCount%LOG_INTERVAL < int64(len(buf2)) {
					log.Printf("[READ] %s: %.2f MB", filename, float64(readCount)/1024/1024)
				}

				if _, errW := compWriter.Write(buf2[:n]); errW != nil {
					log.Printf("[DEFLATE] write error: %v", errW)
					break
				}
			}

			if err != nil {
				if err != io.EOF {
					log.Printf("[READ] err: %v", err)
				}
				compWriter.Close()
				compPw.Close()
				break
			}
		}

		log.Printf("[DEFLATE] %s: finished, waiting encrypt goroutine…", filename)
		wg.Wait()
		log.Printf("[PIPE] %s: encrypt done, closing pw", filename)
		pw.Close()
	}()

	log.Println("[MINIO] Uploading to MinIO…")

	info, err := minioClient.PutObject(
		context.Background(),
		cfg.Bucket,
		objectName,
		pr,
		-1,
		minio.PutObjectOptions{},
	)
	if err != nil {
		log.Printf("[MINIO] PutObject error: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}

	log.Printf("[MINIO] Upload done. Stored size: %.2f MB", float64(info.Size)/1024/1024)

	// 🔥 CALLBACK KE LARAVEL (async)
	go sendCallback(CallbackPayload{
		BackupID:     backupID,
		Filename:     filename,
		MinioPath:    objectName,
		OriginalSize: originalSize,
		FinalSize:    info.Size,
		DurationMs:   time.Since(start).Milliseconds(),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"minio_path":    objectName,
		"final_size":    info.Size,
		"original_size": originalSize,
		"message":       "uploaded",
	})

}

/* ======================================================
   INTEGRITY CHECK (decrypt + decompress + hash)
====================================================== */

func IntegrityHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		http.Error(w, "path required", 400)
		return
	}

	start := time.Now()
	log.Println("──────────────────────────────────────────────")
	log.Printf("[INTEGRITY] Start check for %s", path)

	obj, err := minioClient.GetObject(
		context.Background(),
		cfg.Bucket,
		path,
		minio.GetObjectOptions{},
	)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	pr, pw := io.Pipe()

	// Decrypt goroutine
	go func() {
		defer pw.Close()

		block, _ := aes.NewCipher(aesKey)
		aead, _ := cipher.NewGCM(block)

		var decCount int64

		for {
			nonce := make([]byte, aead.NonceSize())
			if _, err := io.ReadFull(obj, nonce); err != nil {
				if err != io.EOF {
					log.Printf("[DECRYPT] read nonce err: %v", err)
				}
				return
			}

			clen, err := readUint64(obj)
			if err != nil {
				log.Printf("[DECRYPT] read length err: %v", err)
				return
			}

			ciphertext := make([]byte, clen)
			if _, err := io.ReadFull(obj, ciphertext); err != nil {
				log.Printf("[DECRYPT] read ciphertext err: %v", err)
				return
			}

			plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				log.Printf("[DECRYPT] GCM open err: %v", err)
				pw.CloseWithError(err)
				return
			}

			decCount += int64(len(plaintext))
			if decCount%LOG_INTERVAL < int64(len(plaintext)) {
				log.Printf("[DECRYPT] %.2f MB", float64(decCount)/1024/1024)
			}

			if _, err := pw.Write(plaintext); err != nil {
				log.Printf("[DECRYPT] pipe write err: %v", err)
				return
			}
		}
	}()

	// Decompress + hash
	flateR := flate.NewReader(pr)
	defer flateR.Close()

	hasher := sha256.New()
	var hashCount int64
	buf := make([]byte, 1024*1024)

	for {
		n, err := flateR.Read(buf)
		if n > 0 {
			hashCount += int64(n)
			if hashCount%LOG_INTERVAL < int64(len(buf)) {
				log.Printf("[HASH] %.2f MB", float64(hashCount)/1024/1024)
			}
			hasher.Write(buf[:n])
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[HASH] read err: %v", err)
			}
			break
		}
	}

	hashFinal := fmt.Sprintf("%x", hasher.Sum(nil))
	elapsed := time.Since(start)
		log.Printf("[INTEGRITY] DONE %s — decrypted + hashed %.2f MB in %d ms",
		path,
		float64(hashCount)/1024/1024,
		elapsed.Milliseconds(),
	)

	log.Printf("[INTEGRITY] Completed in %d ms", elapsed.Milliseconds())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"hash_after": hashFinal,
		"time_ms":    elapsed.Milliseconds(),
	})
}

/* ======================================================
   DOWNLOAD HANDLER (RAW ENCRYPTED)
   → kalau mau download file .enc apa adanya
====================================================== */

func DownloadHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	filename := r.URL.Query().Get("filename")

	if path == "" {
		http.Error(w, "path required", 400)
		return
	}
	if filename == "" {
		filename = "download.bin"
	}

	log.Printf("[DOWNLOAD] Encrypted %s → %s", path, filename)

	obj, err := minioClient.GetObject(
		context.Background(),
		cfg.Bucket,
		path,
		minio.GetObjectOptions{},
	)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s.enc"`, filename))

	if _, err := io.Copy(w, obj); err != nil {
		log.Printf("[DOWNLOAD] Stream error: %v", err)
	}
}

/* ======================================================
   DOWNLOAD DECRYPTED HANDLER
====================================================== */

func DownloadDecryptedHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	filename := r.URL.Query().Get("filename")

	if path == "" {
		http.Error(w, "path required", 400)
		return
	}
	if filename == "" {
		filename = "restore.bin"
	}

	log.Printf("[DOWNLOAD-DECRYPT] %s → %s", path, filename)

	obj, err := minioClient.GetObject(
		context.Background(),
		cfg.Bucket,
		path,
		minio.GetObjectOptions{},
	)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"`, filename))

	block, _ := aes.NewCipher(aesKey)
	aead, _ := cipher.NewGCM(block)

	pr, pw := io.Pipe()

	// decrypt goroutine
	go func() {
		defer pw.Close()

		var decCount int64

		for {
			nonce := make([]byte, aead.NonceSize())
			if _, err := io.ReadFull(obj, nonce); err != nil {
				if err != io.EOF {
					log.Printf("[DOWNLOAD-DECRYPT] read nonce err: %v", err)
				}
				return
			}

			clen, err := readUint64(obj)
			if err != nil {
				log.Printf("[DOWNLOAD-DECRYPT] read length err: %v", err)
				return
			}

			ciphertext := make([]byte, clen)
			if _, err := io.ReadFull(obj, ciphertext); err != nil {
				log.Printf("[DOWNLOAD-DECRYPT] read ciphertext err: %v", err)
				return
			}

			plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				log.Printf("[DOWNLOAD-DECRYPT] GCM open err: %v", err)
				pw.CloseWithError(err)
				return
			}

			decCount += int64(len(plaintext))
			if decCount%LOG_INTERVAL < int64(len(plaintext)) {
				log.Printf("[DOWNLOAD-DECRYPT] decrypted %.2f MB", float64(decCount)/1024/1024)
			}

			if _, err := pw.Write(plaintext); err != nil {
				log.Printf("[DOWNLOAD-DECRYPT] pipe write err: %v", err)
				return
			}
		}
	}()

	// decompress & stream ke browser
	flateR := flate.NewReader(pr)
	defer flateR.Close()

	bytesWritten, err := io.Copy(w, flateR)

	if err != nil {
		log.Printf("[DOWNLOAD-DECRYPT] Stream error: %v", err)
	} else {
		log.Printf("[DOWNLOAD-DECRYPT] Completed, sent %.2f MB", float64(bytesWritten)/1024/1024)
	}
}

/* ======================================================
   SEND CALLBACK
====================================================== */

func sendCallback(payload CallbackPayload) {
	if cfg.CallbackURL == "" {
		log.Println("[CALLBACK] Skipped, no callback_url in config")
		return
	}

	jsonData, _ := json.Marshal(payload)
	log.Printf("[CALLBACK] Sending to %s: %s", cfg.CallbackURL, string(jsonData))

	resp, err := http.Post(
		cfg.CallbackURL,
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		log.Printf("[CALLBACK] Failed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("[CALLBACK] Laravel responded %d: %s", resp.StatusCode, string(body))
}


/* ======================================================
   DELETE HANDLER (hapus file dari MinIO)
====================================================== */
func DeleteHandler(w http.ResponseWriter, r *http.Request) {
    pathEnc := r.URL.Query().Get("path")
    if pathEnc == "" {
        http.Error(w, "path required", 400)
        return
    }

    path, _ := url.QueryUnescape(pathEnc)
    log.Printf("[DELETE] Attempt delete: %s", path)

    err := minioClient.RemoveObject(
        context.Background(),
        cfg.Bucket,
        path,
        minio.RemoveObjectOptions{},
    )
    if err != nil {
        log.Printf("[DELETE] Failed: %v", err)
        http.Error(w, "delete failed", 500)
        return
    }

    log.Printf("[DELETE] SUCCESS: %s", path)

    json.NewEncoder(w).Encode(map[string]any{
        "deleted": true,
        "path":    path,
    })
}

/* ======================================================
   MAIN
====================================================== */

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")
		if r.Method == http.MethodOptions {
			w.WriteHeader(200)
			return
		}
		h(w, r)
	}
}

func main() {
	runtime.GOMAXPROCS(2)
	loadConfig()
	initMinio()

	http.HandleFunc("/upload", withCORS(UploadHandler))
	http.HandleFunc("/integrity", withCORS(IntegrityHandler))
	http.HandleFunc("/download", withCORS(DownloadHandler))
	http.HandleFunc("/download/decrypted", withCORS(DownloadDecryptedHandler))
	http.HandleFunc("/delete", withCORS(DeleteHandler))

	log.Println("[SERVER] Listening on", cfg.Listen)
	log.Fatal(http.ListenAndServe(cfg.Listen, nil))
}
