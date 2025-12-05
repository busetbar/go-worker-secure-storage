package main

type Config struct {
    MinioEndpoint  string
    MinioKey       string
    MinioSecret    string
    MinioBucket    string
    EncryptionKey  []byte
}