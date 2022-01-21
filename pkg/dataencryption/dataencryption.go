package dataencryption

import (
	"io"
	"os"

	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"

	"github.com/gardener/etcd-backup-restore/pkg/types"
)

const dataEncryptionKeyEnvName = "DATA_ENCRYPTION_KEY"

var dataEncryptionKey = []byte(os.Getenv(dataEncryptionKeyEnvName))

func DecorateSnapStore(snapstore types.SnapStore) types.SnapStore {
	if len(dataEncryptionKey) == 0 {
		return snapstore
	}

	return &decoratedSnapStore{snapstore: snapstore}
}

func decorateReadCloser(snapName []byte, rc io.ReadCloser) io.ReadCloser {
	iv := snapName // use snapName as the initial vector
	stream := makeAesOfbStream(iv, dataEncryptionKey)
	return &readerCloser{r: &cipher.StreamReader{S: stream, R: rc}, c: rc}
}

func makeAesOfbStream(iv []byte, key []byte) cipher.Stream {
	_key := sha256.Sum256(key)

	block, err := aes.NewCipher(_key[:])
	if err != nil {
		panic(err)
	}

	_iv := sha1.Sum(iv)

	stream := cipher.NewOFB(block, _iv[:aes.BlockSize])
	return stream
}
