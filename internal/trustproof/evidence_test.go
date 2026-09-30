package trustproof

import (
	"errors"
	"reflect"
	"testing"
)

func TestTokenize(t *testing.T) {
	got := tokenize("The Quick, brown-fox2 a I  AES-256!")
	// Lowercased alphanumerics; stopwords ("the", "a") and single-char tokens
	// ("i") dropped; hyphen and digits split/kept correctly.
	want := []string{"quick", "brown", "fox2", "aes", "256"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tokenize = %v, want %v", got, want)
	}
}

func TestTermSetOfDeduplicates(t *testing.T) {
	set := termSetOf([]string{"a", "b", "a"})
	if len(set) != 2 {
		t.Errorf("termSetOf len = %d, want 2", len(set))
	}
}

func TestSplitPassagesBlocksAndLines(t *testing.T) {
	content := "first block line one\nfirst block line two\n\n\nsecond block\n\n   \n"
	ps := splitPassages("doc.md", content)
	if len(ps) != 2 {
		t.Fatalf("expected 2 passages, got %d", len(ps))
	}
	if ps[0].Line != 1 || ps[1].Line != 5 {
		t.Errorf("start lines = %d,%d want 1,5", ps[0].Line, ps[1].Line)
	}
	if ps[0].File != "doc.md" {
		t.Errorf("file = %q", ps[0].File)
	}
	if ps[0].Text != "first block line one\nfirst block line two" {
		t.Errorf("unexpected text %q", ps[0].Text)
	}
}

func TestSplitPassagesDropsTermlessBlocks(t *testing.T) {
	// A block with only stopwords/punctuation yields no terms and is dropped.
	ps := splitPassages("doc.md", "the a an it\n\nreal content here")
	if len(ps) != 1 {
		t.Fatalf("expected 1 passage, got %d", len(ps))
	}
	if ps[0].Line != 3 {
		t.Errorf("start line = %d, want 3", ps[0].Line)
	}
}

func TestBuildPassagesReadError(t *testing.T) {
	walkFn := func(fn func(abs, rel string) error) error {
		return fn("/abs/x.txt", "x.txt")
	}
	readErr := errors.New("boom")
	_, err := buildPassages(walkFn, func(string) ([]byte, error) { return nil, readErr })
	if !errors.Is(err, readErr) {
		t.Errorf("expected read error, got %v", err)
	}
}

func TestBuildPassagesWalkError(t *testing.T) {
	walkErr := errors.New("walk failed")
	_, err := buildPassages(
		func(func(abs, rel string) error) error { return walkErr },
		func(string) ([]byte, error) { return nil, nil },
	)
	if !errors.Is(err, walkErr) {
		t.Errorf("expected walk error, got %v", err)
	}
}

func TestBuildPassagesSuccess(t *testing.T) {
	walkFn := func(fn func(abs, rel string) error) error {
		return fn("/abs/a.md", "a.md")
	}
	ps, err := buildPassages(walkFn, func(string) ([]byte, error) {
		return []byte("alpha beta"), nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ps) != 1 || ps[0].File != "a.md" {
		t.Errorf("unexpected passages %+v", ps)
	}
}

func TestReadEvidenceDirBadRoot(t *testing.T) {
	if _, err := readEvidenceDir("/no/such/evidence/dir"); err == nil {
		t.Error("expected error for missing evidence dir")
	}
}

func TestReadEvidenceDirSuccess(t *testing.T) {
	ps, err := readEvidenceDir("testdata/evidence")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ps) == 0 {
		t.Fatal("expected passages from fixture evidence")
	}
}
