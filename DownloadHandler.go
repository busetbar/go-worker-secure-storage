package main

import (
    "compress/flate"
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "io"
    "net/http"

    "github.com/minio/minio-go/v7"
    "github.com/minio/minio-go/v7/pkg/credentials"
    "context"
)

func DownloadHandler(w http.ResponseWriter, r *http.Request, cfg *Config) {
    filename := r.URL.Query().Get("filename")

    minioClient, _ := minio.New(cfg.MinioEndpoint, &minio.Options{
        Creds:  credentials.NewStaticV4(cfg.MinioKey, cfg.MinioSecret, ""),
        Secure: false,
    })

    obj, _ := minioClient.GetObject(context.Background(), cfg.MinioBucket, filename, minio.GetObjectOptions{})

    block, _ := aes.NewCipher(cfg.EncryptionKey)
    aesgcm, _ := cipher.NewGCM(block)

    nonce := make([]byte, aesgcm.NonceSize())
    io.ReadFull(obj, nonce)

    decrypted := cipher.StreamReader{
        S: cipher.NewCTR(block, nonce),
        R: obj,
    }

    inflater := flate.NewReader(decrypted)

    w.Header().Set("Content-Disposition", "attachment; filename="+filename)
    io.Copy(w, inflater)
}
