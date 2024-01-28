package tuf

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

func TUFUpdater(localMetadataDir, localArtifactDir, metadataURL, targetsURL string, root []byte) (*updater.Updater, error) {
	cfg, err := config.New(metadataURL, root) // default config
	if err != nil {
		return nil, err
	}

	cfg.LocalMetadataDir = localMetadataDir
	cfg.LocalTargetsDir = localArtifactDir
	if err != nil {
		return nil, err
	}
	cfg.RemoteTargetsURL = targetsURL
	cfg.PrefixTargetsWithHash = false

	// create a new Updater instance
	up, err := updater.New(cfg)
	return up, err
}

// DownloadTarget downloads the target file using Updater. The Updater refreshes the top-level metadata,
// get the target information, verifies if the target is already cached, and in case it
// is not cached, downloads the target file.
func DownloadTarget(artifact string, updater *updater.Updater) error {

	log := metadata.GetLogger()

	// search if the desired target is available
	targetInfo, err := updater.GetTargetInfo(artifact)
	if err != nil {
		return fmt.Errorf("target %s not found", artifact)
	}

	// target is available, so let's see if the target is already present locally
	path, _, err := updater.FindCachedTarget(targetInfo, "")
	if err != nil {
		return fmt.Errorf("failed while finding a cached target: %w", err)
	}
	if path != "" {
		log.Info("Target is already present", "target", updater, "path", path)
	}

	// target is not present locally, so let's try to download it
	path, _, err = updater.DownloadTarget(targetInfo, "", "")
	if err != nil {
		return fmt.Errorf("failed to download target file %s - %w", artifact, err)
	}

	log.Info("Successfully downloaded target", "target", artifact, "path", path)

	return nil
}

func LoadTrustedRoot(filepath string) (*metadata.Metadata[metadata.RootType], error) {
	RootMetadata, err := metadata.Root().FromFile(filepath)
	if err != nil {
		return nil, err
	}

	return RootMetadata, nil

}

// Get Root from uri, which can be http/s or file
func GetRoot(uri string) ([]byte, error) {
	var rootBytes []byte
	u, _ := url.Parse(uri)
	if u.Scheme == "http" || u.Scheme == "https" {
		response, err := http.Get(uri)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()

		rb, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		rootBytes = rb
	} else {
		RootMetadata, err := LoadTrustedRoot(uri)
		if err != nil {
			return nil, err
		}
		rb, err := RootMetadata.ToBytes(false)
		if err != nil {
			return nil, err
		}
		rootBytes = rb
	}

	return rootBytes, nil
}
