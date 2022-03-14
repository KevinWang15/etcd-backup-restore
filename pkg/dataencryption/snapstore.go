package dataencryption

import (
	"fmt"
	"io"
	"os"

	"crypto/sha256"

	"github.com/minio/sio"
	"golang.org/x/crypto/hkdf"

	"github.com/gardener/etcd-backup-restore/pkg/types"
)

const dataEncryptionKeyEnvName = "DATA_ENCRYPTION_KEY"

var dataEncryptionKey = []byte(os.Getenv(dataEncryptionKeyEnvName))

type decoratedSnapStore struct {
	snapstore types.SnapStore
}

func (r *decoratedSnapStore) deriveEncryptionKey(snapshot types.Snapshot) ([32]byte, error) {
	var key [32]byte
	nonce := snapshot.SnapName // use snapName as the nonce
	kdf := hkdf.New(sha256.New, dataEncryptionKey, []byte(nonce), nil)
	if _, err := io.ReadFull(kdf, key[:]); err != nil {
		return [32]byte{}, err
	}
	return key, nil
}

func (r *decoratedSnapStore) Fetch(snapshot types.Snapshot) (io.ReadCloser, error) {
	key, err := r.deriveEncryptionKey(snapshot)
	if err != nil {
		return nil, fmt.Errorf("deriveEncryptionKey failed as %v", err)
	}

	originalEncryptedDataReader, err := r.snapstore.Fetch(snapshot)
	decryptedDataReader, err := sio.DecryptReader(originalEncryptedDataReader, sio.Config{Key: key[:]})
	if err != nil {
		return nil, fmt.Errorf("sio.DecryptReader failed as %v", err)
	}

	return &readerCloser{r: decryptedDataReader, c: originalEncryptedDataReader}, err
}

func (r *decoratedSnapStore) List() (types.SnapList, error) {
	return r.snapstore.List()
}

func (r *decoratedSnapStore) Save(snapshot types.Snapshot, originalUnencryptedDataReader io.ReadCloser) error {
	key, err := r.deriveEncryptionKey(snapshot)
	if err != nil {
		return fmt.Errorf("deriveEncryptionKey failed as %v", err)
	}

	encryptedDataReader, err := sio.EncryptReader(originalUnencryptedDataReader, sio.Config{Key: key[:]})
	if err != nil {
		return fmt.Errorf("sio.EncryptReader failed as %v", err)
	}

	return r.snapstore.Save(snapshot, &readerCloser{r: encryptedDataReader, c: originalUnencryptedDataReader})
}

func (r *decoratedSnapStore) Delete(snapshot types.Snapshot) error {
	return r.snapstore.Delete(snapshot)
}

func DecorateSnapStore(snapstore types.SnapStore) types.SnapStore {
	if len(dataEncryptionKey) == 0 {
		return snapstore
	}

	return &decoratedSnapStore{snapstore: snapstore}
}
