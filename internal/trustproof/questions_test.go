package trustproof

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseQuestionsDispatch(t *testing.T) {
	csv := []byte("Question\nfrom csv?")
	if got, _ := parseQuestions("q.csv", csv); !reflect.DeepEqual(got, []string{"from csv?"}) {
		t.Errorf("csv dispatch = %v", got)
	}
	md := []byte("- from md?")
	if got, _ := parseQuestions("q.md", md); !reflect.DeepEqual(got, []string{"from md?"}) {
		t.Errorf("md dispatch = %v", got)
	}
	if got, _ := parseQuestions("q.markdown", md); !reflect.DeepEqual(got, []string{"from md?"}) {
		t.Errorf(".markdown dispatch = %v", got)
	}
	txt := []byte("from text?")
	if got, _ := parseQuestions("q.rst", txt); !reflect.DeepEqual(got, []string{"from text?"}) {
		t.Errorf("text dispatch = %v", got)
	}
}

func TestParseTextQuestions(t *testing.T) {
	got := parseTextQuestions([]byte("  one? \n\n  two?\n"))
	want := []string{"one?", "two?"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseTextQuestions = %v, want %v", got, want)
	}
}

func TestParseCSVQuestions(t *testing.T) {
	data := []byte("Question,Notes\nfirst real?,n1\n,skip-empty-first\nsecond real?,n2\n")
	got, err := parseCSVQuestions(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"first real?", "second real?"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseCSVQuestions = %v, want %v", got, want)
	}
}

func TestParseCSVQuestionsNoHeader(t *testing.T) {
	// When the first cell is a real question (not a header label), it is kept.
	got, err := parseCSVQuestions([]byte("is this kept?\nand this?"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"is this kept?", "and this?"}) {
		t.Errorf("unexpected: %v", got)
	}
}

func TestParseCSVQuestionsMalformed(t *testing.T) {
	// A bare quote in an unquoted field makes encoding/csv fail.
	if _, err := parseCSVQuestions([]byte(`ab"cd,x`)); err == nil {
		t.Error("expected CSV parse error")
	}
}

func TestIsHeaderCell(t *testing.T) {
	for _, h := range []string{"Question", "questions", "CONTROL", "Requirement"} {
		if !isHeaderCell(h) {
			t.Errorf("isHeaderCell(%q) = false, want true", h)
		}
	}
	for _, q := range []string{"Do you encrypt data?", "mfa"} {
		if isHeaderCell(q) {
			t.Errorf("isHeaderCell(%q) = true, want false", q)
		}
	}
}

func TestParseMarkdownQuestions(t *testing.T) {
	md := []byte(strings.Join([]string{
		"# Heading skipped",
		"",
		"- bullet question?",
		"* star question?",
		"1. numbered question?",
		"2) paren question?",
		"---",
		"plain question?",
	}, "\n"))
	got := parseMarkdownQuestions(md)
	want := []string{
		"bullet question?", "star question?", "numbered question?",
		"paren question?", "plain question?",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseMarkdownQuestions = %v, want %v", got, want)
	}
}

func TestIsHorizontalRule(t *testing.T) {
	cases := map[string]bool{
		"-":         false, // too short
		"--":        false, // too short
		"---":       true,
		"-----":     true,
		"***":       true,
		"plain":     false,
		"# heading": false,
	}
	for in, want := range cases {
		if got := isHorizontalRule(in); got != want {
			t.Errorf("isHorizontalRule(%q) = %v, want %v", in, got, want)
		}
	}
}
