package dataencryption

import (
	"io"

	"github.com/gardener/etcd-backup-restore/pkg/types"
)

type decoratedSnapStore struct {
	snapstore types.SnapStore
}

func (r *decoratedSnapStore) Fetch(snapshot types.Snapshot) (io.ReadCloser, error) {
	rc, err := r.snapstore.Fetch(snapshot)
	if err != nil {
		return rc, err
	}

	return decorateReadCloser([]byte(snapshot.SnapName), rc), nil
}

func (r *decoratedSnapStore) List() (types.SnapList, error) {
	return r.snapstore.List()
}

func (r *decoratedSnapStore) Save(snapshot types.Snapshot, rc io.ReadCloser) error {
	decoratedRc := decorateReadCloser([]byte(snapshot.SnapName), rc)
	return r.snapstore.Save(snapshot, decoratedRc)
}

func (r *decoratedSnapStore) Delete(snapshot types.Snapshot) error {
	return r.snapstore.Delete(snapshot)
}
