// Conformance runner for the Go SDK (tests/conformance/sdk/README.md).
//
//	go build -o conformance-go ./conformance && ./conformance-go <op> [key=value ...]
package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	sourceorrery "github.com/netizine/sourceorrery/bindings/go"
)

type kv [][2]string

func (l *kv) add(key, value string) { *l = append(*l, [2]string{key, value}) }

func properties(l *kv, p sourceorrery.SecretProperties) {
	l.add("version", p.Version)
	l.add("enabled", fmt.Sprint(p.Enabled))
	l.add("content_type", p.ContentType)
	l.add("reference", p.Reference())
	for k, v := range p.Tags {
		l.add("tag."+k, v)
	}
}

func secret(l *kv, s *sourceorrery.Secret) {
	l.add("value", s.Value.Text())
	properties(l, s.Properties)
}

func run(op string, args map[string]string) (kv, error) {
	var lines kv
	vault := args["vault"]
	if vault == "" {
		vault = os.Getenv("SOURCEORRERY_TEST_VAULT")
	}
	if vault == "" {
		vault = "development"
	}
	opts := &sourceorrery.OpenOptions{
		Home:              args["home"],
		RecoveryKeyFile:   args["recovery_key_file"],
		IgnoreEnvironment: args["environment"] == "false",
	}
	if p, ok := args["recovery_key"]; ok {
		opts.RecoveryKey = []byte(p)
	}
	if op == "load" {
		project, err := sourceorrery.LoadProject(args["manifest"], opts)
		if err != nil {
			return nil, err
		}
		defer project.Close()
		names := make([]string, 0, len(project.Secrets))
		for _, s := range project.Secrets {
			names = append(names, s.Name)
		}
		sort.Strings(names)
		lines.add("project.name", project.Name)
		lines.add("project.count", fmt.Sprint(len(project.Secrets)))
		lines.add("project.names", strings.Join(names, ","))
		for _, s := range project.Secrets {
			lines.add("secret."+s.Env, s.Value.Text())
		}
		return lines, nil
	}
	reader, err := sourceorrery.Open(vault, opts)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	switch op {
	case "open":
		d, err := reader.Descriptor()
		if err != nil {
			return nil, err
		}
		lines.add("descriptor.name", d.Name)
		lines.add("descriptor.protectors", strings.Join(d.Protectors, ","))
	case "get":
		var s *sourceorrery.Secret
		if v, ok := args["version"]; ok {
			s, err = reader.GetVersion(args["name"], v)
		} else {
			s, err = reader.Get(args["name"])
		}
		if err != nil {
			return nil, err
		}
		defer s.Close()
		secret(&lines, s)
	case "get-newest-explicit":
		newest, err := reader.Properties(args["name"], "")
		if err != nil {
			return nil, err
		}
		s, err := reader.GetVersion(args["name"], newest.Version)
		if err != nil {
			return nil, err
		}
		defer s.Close()
		secret(&lines, s)
	case "properties":
		p, err := reader.Properties(args["name"], args["version"])
		if err != nil {
			return nil, err
		}
		properties(&lines, p)
	case "resolve":
		s, err := reader.Resolve(args["reference"])
		if err != nil {
			return nil, err
		}
		defer s.Close()
		secret(&lines, s)
	default:
		return nil, fmt.Errorf("unknown scenario op %q", op)
	}
	return lines, nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: conformance <op> [key=value ...]")
		os.Exit(2)
	}
	args := map[string]string{}
	for _, arg := range os.Args[2:] {
		if i := strings.IndexByte(arg, '='); i > 0 {
			args[arg[:i]] = arg[i+1:]
		}
	}
	lines, err := run(os.Args[1], args)
	if err != nil {
		var soErr *sourceorrery.Error
		if !errors.As(err, &soErr) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		lines = kv{{"outcome", "error"}, {"code", soErr.Code}, {"message", soErr.Message}, {"hint", soErr.Hint},
			{"transient", fmt.Sprint(soErr.Transient())}, {"type", "*sourceorrery.Error"}}
	} else {
		lines = append(kv{{"outcome", "ok"}}, lines...)
	}
	for _, l := range lines {
		fmt.Printf("%s\t%s\n", l[0], l[1])
	}
}
