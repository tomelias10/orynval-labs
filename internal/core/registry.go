package core

import (
	"fmt"
	"sort"
	"sync"
)

// Registry holds the set of rules a tool will run. Register adds a rule;
// Evaluate runs them all against a Context and returns deduplicated, sorted
// findings. A Registry is safe for concurrent registration but Evaluate is
// intended to be called once the rule set is assembled.
type Registry struct {
	mu    sync.Mutex
	rules []Rule
	ids   map[string]struct{}
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{ids: make(map[string]struct{})}
}

// Register adds a rule. It panics on a nil rule, an empty ID, or a duplicate
// ID: these are programming errors that should surface at startup, not silently
// corrupt a scan.
func (r *Registry) Register(rule Rule) {
	if rule == nil {
		panic("core: Register(nil rule)")
	}
	id := rule.ID()
	if id == "" {
		panic("core: Register rule with empty ID")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.ids[id]; dup {
		panic(fmt.Sprintf("core: duplicate rule ID %q", id))
	}
	r.ids[id] = struct{}{}
	r.rules = append(r.rules, rule)
}

// Rules returns the registered rules ordered by ID, so callers that list or
// document rules get a stable order regardless of registration order.
func (r *Registry) Rules() []Rule {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Rule, len(r.rules))
	copy(out, r.rules)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Len reports how many rules are registered.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.rules)
}

// Evaluate runs every registered rule against ctx, then dedupes by fingerprint
// and sorts the combined findings deterministically. Rules run in ID order so
// that any (buggy) cross-rule ordering assumptions still produce stable output.
func (r *Registry) Evaluate(ctx *Context) []Finding {
	rules := r.Rules() // sorted copy
	var all []Finding
	for _, rule := range rules {
		all = append(all, rule.Evaluate(ctx)...)
	}
	all = DedupeFindings(all)
	SortFindings(all)
	return all
}
