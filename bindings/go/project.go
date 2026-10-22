package sourceorrery

/*
#include "sourceorrery.h"
*/
import "C"

import "encoding/json"

// ProjectSecret is one secret resolved from sourceorrery.toml.
type ProjectSecret struct {
	Name       string
	Env        string
	Reference  string
	Required   bool
	Properties SecretProperties
	Value      *SecretValue
}

// Project is the set of secrets a sourceorrery.toml declares, resolved like
// `sourceorrery run`: every required secret must resolve or LoadProject
// returns that secret's error; optional secrets that are missing, refused by
// policy or whose vault does not exist are left out.
type Project struct {
	// Name is [project].name.
	Name string
	// ManifestPath is the manifest file that was loaded.
	ManifestPath string
	// Secrets lists every secret that resolved, in manifest order.
	Secrets []ProjectSecret
}

type projectInfoJSON struct {
	Name         string `json:"name"`
	ManifestPath string `json:"manifest_path"`
	Count        int    `json:"count"`
}

type projectEntryJSON struct {
	Name       string           `json:"name"`
	Env        string           `json:"env"`
	Reference  string           `json:"reference"`
	Required   bool             `json:"required"`
	Properties SecretProperties `json:"properties"`
}

// LoadProject loads manifest (empty: the nearest sourceorrery.toml above
// the current directory) and resolves every entry. opts apply to every
// vault the manifest names.
func LoadProject(manifest string, opts *OpenOptions) (*Project, error) {
	if err := requireAbi(); err != nil {
		return nil, err
	}
	optionsJSON := opts.json()
	passphrase := opts.passphrase()
	var handle *C.so_project
	err := call(func() C.so_status {
		return C.so_project_load(
			bytesPtr([]byte(manifest)), C.size_t(len(manifest)),
			bytesPtr(optionsJSON), C.size_t(len(optionsJSON)),
			bytesPtr(passphrase), C.size_t(len(passphrase)),
			&handle)
	})
	if err != nil {
		return nil, err
	}
	defer C.so_project_free(handle)

	var infoBytes C.so_bytes
	if err := call(func() C.so_status { return C.so_project_info(handle, &infoBytes) }); err != nil {
		return nil, err
	}
	var info projectInfoJSON
	if err := json.Unmarshal(takeBytes(&infoBytes), &info); err != nil {
		return nil, err
	}
	project := &Project{Name: info.Name, ManifestPath: info.ManifestPath}
	count := int(C.so_project_count(handle))
	for index := 0; index < count; index++ {
		var entryBytes, valueBytes C.so_bytes
		i := index
		err := call(func() C.so_status {
			return C.so_project_entry(handle, C.size_t(i), &entryBytes, &valueBytes)
		})
		if err != nil {
			project.Close()
			return nil, err
		}
		value := newValue(&valueBytes)
		var entry projectEntryJSON
		if err := json.Unmarshal(takeBytes(&entryBytes), &entry); err != nil {
			value.Close()
			project.Close()
			return nil, err
		}
		project.Secrets = append(project.Secrets, ProjectSecret{
			Name:       entry.Name,
			Env:        entry.Env,
			Reference:  entry.Reference,
			Required:   entry.Required,
			Properties: entry.Properties,
			Value:      value,
		})
	}
	return project, nil
}

// Get returns the entry declared as [secrets.<name>], if it resolved.
func (p *Project) Get(name string) *ProjectSecret {
	for i := range p.Secrets {
		if p.Secrets[i].Name == name {
			return &p.Secrets[i]
		}
	}
	return nil
}

// Env returns the value delivered in environment variable env, if any.
func (p *Project) Env(env string) *SecretValue {
	for i := range p.Secrets {
		if p.Secrets[i].Env == env {
			return p.Secrets[i].Value
		}
	}
	return nil
}

// Close zeroises every value.
func (p *Project) Close() {
	for i := range p.Secrets {
		p.Secrets[i].Value.Close()
	}
}
