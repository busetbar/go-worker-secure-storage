package main

import (
    "compress/flate"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "io"
    "net/http"

    "github.com/minio/minio-go/v7"
    "github.com/minio/minio-go/v7/pkg/credentials"
    "context"
)

func UploadHandler(w http.ResponseWriter, r *http.Request, cfg *Config) {
    filename := r.URL.Query().Get("filename")
    if filename == "" {
        http.Error(w, "Filename required", 400)
        return
    }

    // Connect MinIO
    minioClient, _ := minio.New(cfg.MinioEndpoint, &minio.Options{
        Creds:  credentials.NewStaticV4(cfg.MinioKey, cfg.MinioSecret, ""),
        Secure: false,
    })

    // AES init
    block, _ := aes.NewCipher(cfg.EncryptionKey)
    aesgcm, _ := cipher.NewGCM(block)

    nonce := make([]byte, aesgcm.NonceSize())
    io.ReadFull(rand.Reader, nonce)

    // Create pipe
    pr, pw := io.Pipe()

    go func() {
        defer pw.Close()

        // 1. Compress → 2. Encrypt → Pipe Writer
        compressor, _ := flate.NewWriter(pw, flate.BestCompression)
        encryptedWriter := cipher.StreamWriter{
            S: cipher.NewCTR(block, nonce),
            W: compressor,
        }

        io.Copy(encryptedWriter, r.Body)

        compressor.Close()
    }()

    // Upload to MinIO (streaming multipart)
    uploadInfo, err := minioClient.PutObject(
        context.Background(),
        cfg.MinioBucket,
        filename,
        pr,
        -1,
        minio.PutObjectOptions{
            ContentType: "application/octet-stream",
        },
    )
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }

    response := map[string]interface{}{
        "filename": filename,
        "size":     uploadInfo.Size,
    }
    json.NewEncoder(w).Encode(response)
}
