// rubric_bootstrap.go — loads config/imda_rubric.yaml into a rubric.Config
// and constructs the resolver + dashboard service per Phase B of the O+
// hydration plan atomic-napping-spring.md.
//
// File lookup order:
//
//  1. CHORA_IMDA_RUBRIC_PATH env var — explicit override path.
//  2. ./config/imda_rubric.yaml relative to the binary's CWD (production).
//  3. ../../config/imda_rubric.yaml — local dev (cmd/server run from cmd/server).
//
// On parse / load failure the rubric resolver wiring is skipped and the
// O+ endpoints return 503 — the dashboard usecase MUST receive a real
// resolver, so we fail-soft at boot rather than panic.
//
// Per [[secrets-and-env]] + [[feedback-no-stubs-real-wiring]]: real
// production resolver wired against real evidence.Repository; no
// in-memory stubs at the bootstrap layer.
package main

import (
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/apollo-chora/chora-governance/internal/domain/evidence"
	domainimda "github.com/apollo-chora/chora-governance/internal/domain/imda"
	"github.com/apollo-chora/chora-governance/internal/domain/rubric"
	usecaseimda "github.com/apollo-chora/chora-governance/internal/usecase/imda"
)

// bootstrapRubric wires the rubric resolver + IMDA dashboard service. Both
// returned values are nil when the YAML config cannot be loaded — callers
// MUST be defensive (handler.go skips the O+ routes when nil).
func bootstrapRubric(
	imdaRepo domainimda.Repository,
	evidenceRepo evidence.Repository,
) (*rubric.Resolver, *usecaseimda.Service) {
	cfg, err := loadRubricConfig()
	if err != nil {
		log.Printf("governance: rubric config load failed (O+ endpoints will 503): %v", err)
		return nil, nil
	}
	if evidenceRepo == nil {
		log.Printf("governance: rubric resolver NOT wired — evidence repo is nil")
		return nil, nil
	}
	resolver, err := rubric.NewResolver(cfg, evidenceRepo)
	if err != nil {
		log.Printf("governance: rubric.NewResolver: %v", err)
		return nil, nil
	}
	dashboardSvc, err := usecaseimda.NewService(imdaRepo, resolver)
	if err != nil {
		log.Printf("governance: usecaseimda.NewService: %v", err)
		return resolver, nil
	}
	log.Printf("governance: rubric resolver + IMDA dashboard service wired (dimensions=%d)", len(cfg.Dimensions))
	return resolver, dashboardSvc
}

// loadRubricConfig walks the canonical search paths and returns the first
// parsed config. The candidate list mirrors how production Kubernetes mounts
// the configMap and how local `go run cmd/server` resolves relative paths.
func loadRubricConfig() (rubric.Config, error) {
	candidates := rubricConfigCandidates()
	for _, path := range candidates {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return rubric.Config{}, err
		}
		var cfg rubric.Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return rubric.Config{}, err
		}
		log.Printf("governance: loaded rubric config from %s", path)
		return cfg, nil
	}
	return rubric.Config{}, os.ErrNotExist
}

// rubricConfigCandidates returns the ordered list of paths to probe.
func rubricConfigCandidates() []string {
	out := []string{os.Getenv("CHORA_IMDA_RUBRIC_PATH")}
	// Production CWD (Dockerfile sets WORKDIR /app and the config dir is
	// copied to /app/config/imda_rubric.yaml).
	out = append(out, filepath.Join("config", "imda_rubric.yaml"))
	// Local dev — `go run ./cmd/server` runs from cmd/server/.
	out = append(out, filepath.Join("..", "..", "config", "imda_rubric.yaml"))
	return out
}
