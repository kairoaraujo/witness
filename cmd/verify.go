// Copyright 2021 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"

	witness "github.com/in-toto/go-witness"
	"github.com/in-toto/go-witness/archivista"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/intoto"
	"github.com/in-toto/go-witness/log"
	"github.com/in-toto/go-witness/policy"
	"github.com/in-toto/go-witness/signer/kms"
	"github.com/in-toto/go-witness/source"
	"github.com/in-toto/witness/options"
	"github.com/in-toto/witness/tuf"
	"github.com/spf13/cobra"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

func VerifyCmd() *cobra.Command {
	vo := options.VerifyOptions{
		ArchivistaOptions:          options.ArchivistaOptions{},
		KMSVerifierProviderOptions: options.KMSVerifierProviderOptions{},
		VerifierOptions:            options.VerifierOptions{},
	}
	cmd := &cobra.Command{
		Use:               "verify",
		Short:             "Verifies a witness policy",
		Long:              "Verifies a policy provided key source and exits with code 0 if verification succeeds",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			verifiers, err := loadVerifiers(cmd.Context(), vo.VerifierOptions, vo.KMSVerifierProviderOptions, providersFromFlags("verifier", cmd.Flags()))
			if err != nil {
				return fmt.Errorf("failed to load signer: %w", err)
			}
			return runVerify(cmd.Context(), vo, verifiers...)
		},
	}
	vo.AddFlags(cmd)
	return cmd
}

const (
	MAX_DEPTH = 4
)

func parsePolicySubjectScopes(p *policy.Policy) []policy.SubjectScope {
	var subjectScopes []policy.SubjectScope

	for stepName, _ := range p.Steps {
		for _, attestation := range p.Steps[stepName].Attestations {
			for _, subjectPolicy := range attestation.SubjectScopes {
				subjectScopes = append(subjectScopes, policy.SubjectScope{Subject: attestation.Type + "/" + subjectPolicy.Subject, Scope: subjectPolicy.Scope})
			}
		}
	}
	return subjectScopes
}

// checkValidPolicies checks if the policy is valid
// This code is not optimal and should be refactored
func checkValidPolicies(p *policy.Policy, attestations []string) bool {
	var valid bool = false
	subjectScopes := parsePolicySubjectScopes(p)
	for _, subjectPolicy := range subjectScopes {
		for _, a := range attestations {
			if strings.HasPrefix(a, subjectPolicy.Subject) && strings.Contains(a, subjectPolicy.Scope) {
				valid = true
			}
		}
	}
	if valid {
		log.Debug("Valid Policy: ", p.Name)
	} else {
		log.Debug("Invalid Policy: ", p.Name)
	}
	return valid
}

func getValidPolicies(policies []dsse.Envelope, attestations []string) []dsse.Envelope {
	// Check if the policy is valid
	validPolicies := []dsse.Envelope{}
	policyPayload := &policy.Policy{}
	for _, p := range policies {
		if err := json.Unmarshal(p.Payload, policyPayload); err != nil {
			log.Error("Failed to unmarshal policy payload: ", err)
			continue
		}
		if checkValidPolicies(policyPayload, attestations) {
			validPolicies = append(validPolicies, p)
		}
	}

	return validPolicies
}

// todo: this logic should be broken out and moved to pkg/
// we need to abstract where keys are coming from, etc
func runVerify(ctx context.Context, vo options.VerifyOptions, verifiers ...cryptoutil.Verifier) error {

	var tufUpdater *updater.Updater

	if vo.TUFRoot != "" {
		log.Debug("Using trusted TUF")
		// TUF vars
		var policyPubKey string
		var metadataURL string

		// local TUF metadata directory
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home dir: %w", err)
		}
		localMetadataDir := path.Join(homeDir, ".witness", "tuf", "metadata")
		os.MkdirAll(localMetadataDir, 0755)
		localArtifactDir := path.Join(homeDir, ".witness", "tuf", "artifact")

		rootBytes, err := tuf.GetRoot(vo.TUFRoot)
		if err != nil {
			return fmt.Errorf("failed to get root metadata: %w", err)
		}

		currentRoot, err := metadata.Root().FromBytes(rootBytes)
		if err != nil {
			return fmt.Errorf("failed to load root metadata: %w", err)
		}
		if len(currentRoot.Signed.UnrecognizedFields) != 0 {
			vo.ArchivistaOptions.Url = currentRoot.Signed.UnrecognizedFields["x-archivista-url"].(string)
			metadataURL = currentRoot.Signed.UnrecognizedFields["x-archivista-metadata"].(string)
		}

		// Get the latest Root metadata
		tufUpdater, err = tuf.TUFUpdater(localMetadataDir, localArtifactDir, metadataURL, vo.ArchivistaOptions.Url, rootBytes)
		tufUpdater.Refresh()
		log.Debug("Refreshing TUF")
		if err != nil {
			return fmt.Errorf("failed to create tuf updater: %w", err)
		}
		log.Info("Root Version: ", tufUpdater.GetTrustedMetadataSet().Root.Signed.Version)
		updatedTrustedMetadata := tufUpdater.GetTrustedMetadataSet()
		latestRoot := updatedTrustedMetadata.Root
		// Update the current parameters
		vo.ArchivistaOptions.Enable = true
		vo.ArchivistaOptions.Url = latestRoot.Signed.UnrecognizedFields["x-archivista-url"].(string)

		policyPubKeyId := latestRoot.Signed.Roles["timestamp"].KeyIDs[0]
		if policyPubKeyId == "" {
			return fmt.Errorf("policy public key id not found")
		}
		// There is a bug on go-tuf that doesn't allow to get the public key from the root metadata if it is a RSA
		// policyPubKey := latestRoot.Signed.Keys[policyPubKeyId].Value.PublicKey
		onlineKey := latestRoot.Signed.Keys[policyPubKeyId].UnrecognizedFields["x-rstuf-online-key-uri"].(string)
		if strings.Contains(onlineKey, "awskms:") {
			policyPubKey = strings.Replace(onlineKey, "awskms:", "awskms:///", 1)
			awsOptions := func(ksp *kms.KMSSignerProvider) {
				ksp.Reference = policyPubKey
				ksp.HashFunc = crypto.SHA256
			}
			awsSignerProvider := kms.New(awsOptions)
			awsVerifier, err := awsSignerProvider.Verifier(ctx)
			if err != nil {
				return fmt.Errorf("failed to create verifier: %w", err)
			}
			verifiers = append(verifiers, awsVerifier)

		}

		if strings.Contains(onlineKey, "fn:") {
			policyPubKey := latestRoot.Signed.Keys[policyPubKeyId].Value.PublicKey
			pemVerifier, err := cryptoutil.NewVerifierFromReader(strings.NewReader(policyPubKey))
			if err != nil {
				return fmt.Errorf("failed to create verifier: %w", err)
			}
			verifiers = append(verifiers, pemVerifier)
		}

	} else {
		if vo.KeyPath == "" && len(vo.CAPaths) == 0 && len(verifiers) == 0 {
			return fmt.Errorf("must supply either a public key, CA certificates or a verifier")
		} // else {
		// 	keyFile, err := os.Open(vo.KeyPath)
		// 	if err != nil {
		// 		return fmt.Errorf("failed to open key file: %w", err)
		// 	}
		// 	defer keyFile.Close()

		// 	v, err := cryptoutil.NewVerifierFromReader(keyFile)
		// 	if err != nil {
		// 		return fmt.Errorf("failed to create verifier: %w", err)
		// 	}

		// 	verifiers = append(verifiers, v)
		// }
	}

	subjectsDigests := []cryptoutil.DigestSet{}

	if len(vo.ArtifactFilePath) > 0 {
		artifactDigestSet, err := cryptoutil.CalculateDigestSetFromFile(vo.ArtifactFilePath, []cryptoutil.DigestValue{{Hash: crypto.SHA256, GitOID: false}})
		if err != nil {
			return fmt.Errorf("failed to calculate artifact digest: %w", err)
		}

		subjectsDigests = append(subjectsDigests, artifactDigestSet)
	}

	for _, subDigest := range vo.AdditionalSubjects {
		subjectsDigests = append(subjectsDigests, cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}: subDigest})
	}

	if len(subjectsDigests) == 0 {
		return errors.New("at least one subject is required, provide an artifact file or subject")
	}
	log.Debug("Total number of subjects digests: ", len(subjectsDigests))

	// Load Attestations if given
	var collectionSource source.Sourcer
	memSource := source.NewMemorySource()
	for _, path := range vo.AttestationFilePaths {
		log.Debug("Using local attestation")
		if err := memSource.LoadFile(path); err != nil {
			return fmt.Errorf("failed to load attestation file: %w", err)
		}
	}
	// Load Attestations from Archivista and list attestation subjects
	attSubjects := []string{}
	attScopes := []string{}
	fullAttSubjects := []string{}
	collectionSource = memSource
	validPolicies := []dsse.Envelope{}
	if vo.ArchivistaOptions.Enable {
		archivistaClient := archivista.New(vo.ArchivistaOptions.Url)
		archivistaSource := source.NewArchvistSource(archivistaClient)
		collectionSource = source.NewMultiSource(collectionSource, archivistaSource)

		var digests = []string{}
		for _, set := range subjectsDigests {
			for _, digest := range set {
				digests = append(digests, digest)
			}
		}
		log.Debug("Searching for attestation by subject digests")
		atts, err := archivistaSource.Search(ctx, "", digests, nil)
		if err != nil {
			return fmt.Errorf("failed to search for attestation: %w", err)
		}
		log.Debug("Number of attestation retrieved: ", len(atts))
		attPayload := &intoto.Statement{}
		for _, att := range atts {
			if err := json.Unmarshal(att.Envelope.Payload, attPayload); err != nil {
				return fmt.Errorf("failed to unmarshal attestation payload: %w", err)
			}
			for _, subject := range attPayload.Subject {
				u, err := url.Parse(subject.Name)
				if err != nil {
					return fmt.Errorf("failed to parse subject name: %w", err)
				}
				subjectName := u.Scheme + "://" + u.Host + strings.Split(u.Path, ":")[0]
				if !contains(attSubjects, subjectName) {
					attSubjects = append(attSubjects, subjectName)
					attScopes = append(attScopes, strings.SplitN(u.Path, ":", 2)[1])
				}
				fullAttSubjects = append(fullAttSubjects, subject.Name)
			}
		}

		log.Debug("Searching for policies by attestation subjects in Archivista (", vo.ArchivistaOptions.Url, ")")
		matchPolicies, err := archivistaSource.SearchPoliciesBySubjectsName(ctx, attSubjects, attScopes, vo.ArchivistaOptions.Url, tufUpdater)
		if err != nil {
			return fmt.Errorf("failed to search for policies: %w", err)
		}
		log.Debug("Number of policies retrieved: ", len(matchPolicies))

		validPolicies = getValidPolicies(matchPolicies, fullAttSubjects)
		log.Debug("Number of valid policies (match by Subject Policy): ", len(validPolicies))
	}

	if vo.PolicyFilePath != "" {
		policyEnvelope := dsse.Envelope{}
		inFile, err := os.Open(vo.PolicyFilePath)
		if err != nil {
			return fmt.Errorf("failed to open file to sign: %w", err)
		}

		defer inFile.Close()
		decoder := json.NewDecoder(inFile)
		if err := decoder.Decode(&policyEnvelope); err != nil {
			return fmt.Errorf("could not unmarshal policy envelope: %w", err)
		}

		validPolicies = append(validPolicies, policyEnvelope)
	}

	// Get Artifact Digest to generate subjects
	subjectsD := []cryptoutil.DigestSet{}

	if len(vo.ArtifactFilePath) > 0 {
		artifactDigestSet, err := cryptoutil.CalculateDigestSetFromFile(vo.ArtifactFilePath, []cryptoutil.DigestValue{{Hash: crypto.SHA256, GitOID: false}})
		if err != nil {
			return fmt.Errorf("failed to calculate artifact digest: %w", err)
		}

		subjectsD = append(subjectsD, artifactDigestSet)
	}

	for _, subDigest := range vo.AdditionalSubjects {
		subjectsD = append(subjectsD, cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}: subDigest})
	}

	if len(subjectsD) == 0 {
		return errors.New("at least one subject is required, provide an artifact file or subject")
	}

	// Load Attestations from Archivista
	collectionSource = memSource
	if vo.ArchivistaOptions.Enable {
		collectionSource = source.NewMultiSource(collectionSource, source.NewArchvistSource(archivista.New(vo.ArchivistaOptions.Url)))
	}

	for _, policyEnvelope := range validPolicies {
		verifiedEvidence, err := witness.Verify(
			ctx,
			policyEnvelope,
			verifiers,
			witness.VerifyWithSubjectDigests(subjectsDigests),
			witness.VerifyWithCollectionSource(collectionSource),
		)
		if err != nil {
			return fmt.Errorf("failed to verify policy: %w", err)
		}

		log.Info("Verification succeeded")
		log.Info("Evidence:")
		num := 0
		for _, stepEvidence := range verifiedEvidence {
			for _, e := range stepEvidence {
				log.Info(fmt.Sprintf("%d: %s", num, e.Reference))
				num++
			}
		}
	}
	return nil
}
