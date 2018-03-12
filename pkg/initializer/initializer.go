// Copyright © 2018 The Gardener Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package initializer

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/gardener/etcd-backup-restore/pkg/initializer/validator"
	"github.com/gardener/etcd-backup-restore/pkg/snapshot/restorer"
	"github.com/gardener/etcd-backup-restore/pkg/snapstore"
	"github.com/sirupsen/logrus"
)

const (
	envStorageContainer = "STORAGE_CONTAINER"
	defaultLocalStore   = "default.etcd.bkp"
	backupFormatVersion = "v1"
)

// Initialize has the following steps:
//   * Check if data directory exists.
//     - If data directory exists
//       * Check for data corruption.
//			- If data directory is in corrupted state, clear the data directory.
//     - If data directory does not exist.
//       * Check if Latest snapshot available.
//		   - Try to perform an Etcd data restoration from the latest snapshot.
//		   - No snapshots are available, start etcd as a fresh installation.
func (e *EtcdInitializer) Initialize() error {
	dataDirStatus, err := e.Validator.Validate()
	if err != nil && dataDirStatus != validator.DataDirectoryNotExist {
		err = fmt.Errorf("error while initializing: %v", err)
		return err
	}
	if dataDirStatus != validator.DataDirectoryValid {
		if err = e.restoreCorruptData(); err != nil {
			err = fmt.Errorf("error while restoring corrupt data: %v", err)
		}
	}
	return err
}

//NewInitializer creates an etcd initializer object.
func NewInitializer(options *restorer.RestoreOptions, storageProvider string, logger *logrus.Logger) *EtcdInitializer {

	etcdInit := &EtcdInitializer{
		Config: &Config{
			StorageProvider: storageProvider,
			RestoreOptions:  options,
		},
		Validator: &validator.DataValidator{
			Config: &validator.Config{
				DataDir: options.RestoreDataDir,
			},
			Logger: logger,
		},
		Logger: logger,
	}

	return etcdInit
}

func (e *EtcdInitializer) restoreCorruptData() error {
	logger := e.Logger
	dataDir := e.Config.RestoreOptions.RestoreDataDir
	storageProvider := e.Config.StorageProvider
	logger.Infof("Removing data directory(%s) for snapshot restoration.", dataDir)
	err := os.RemoveAll(filepath.Join(dataDir))
	if err != nil {
		err = fmt.Errorf("failed to delete the Data directory: %v", err)
		return err
	}
	store, err := getSnapstore(storageProvider)
	if err != nil {
		err = fmt.Errorf("failed to create snapstore from configured storage provider: %v", err)
		return err
	}
	logger.Infoln("Finding latest snapshot...")
	snap, err := store.GetLatest()
	if err != nil {
		err = fmt.Errorf("failed to get latest snapshot: %v", err)
		return err
	}
	if snap == nil {
		logger.Infof("No snapshot found. Will do nothing.")
		return err
	}

	logger.Infof("Restoring from latest snapshot: %s...", snap.SnapPath)

	e.Config.RestoreOptions.Snapshot = *snap

	rs := restorer.NewRestorer(store, logger)

	err = rs.Restore(*e.Config.RestoreOptions)
	if err != nil {
		err = fmt.Errorf("Failed to restore snapshot: %v", err)
		return err
	}
	logger.Infoln("Successfully restored the etcd data directory.")
	return err
}

// getSnapstore returns the snapstore object for give storageProvider with specified container
func getSnapstore(storageProvider string) (snapstore.SnapStore, error) {
	switch storageProvider {
	case snapstore.SnapstoreProviderLocal, "":
		container := os.Getenv(envStorageContainer)
		if container == "" {
			container = defaultLocalStore
		}
		return snapstore.NewLocalSnapStore(path.Join(container, backupFormatVersion))
	case snapstore.SnapstoreProviderS3:
		container := os.Getenv(envStorageContainer)
		if container == "" {
			return nil, fmt.Errorf("storage container name not specified")
		}
		return snapstore.NewS3SnapStore(container, backupFormatVersion)
	default:
		return nil, fmt.Errorf("unsupported storage provider : %s", storageProvider)

	}
}
