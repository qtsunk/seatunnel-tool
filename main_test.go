package main

import (
    "net/url"
    "testing"
)

func TestSanitizeBaseURL(t *testing.T) {
    cases := []struct {
        input    string
        expected string
        wantErr  bool
    }{
        {"", "", false},
        {"   http://localhost:8080  ", "http://localhost:8080", false},
        {"https://example.com/seatunnel/", "https://example.com/seatunnel", false},
        {"ftp://example.com", "", true},
        {"example.com", "", true},
        {"http://", "", true},
    }

    for _, tc := range cases {
        got, err := sanitizeBaseURL(tc.input)
        if tc.wantErr {
            if err == nil {
                t.Fatalf("sanitizeBaseURL(%q) expected error", tc.input)
            }
            continue
        }
        if err != nil {
            t.Fatalf("sanitizeBaseURL(%q) unexpected error: %v", tc.input, err)
        }
        if got != tc.expected {
            t.Fatalf("sanitizeBaseURL(%q) = %q, want %q", tc.input, got, tc.expected)
        }
    }
}

func TestBuildTargetURL(t *testing.T) {
    u, err := buildTargetURL("http://localhost:8080", "/overview", map[string]string{"tag": "dev"})
    if err != nil {
        t.Fatalf("buildTargetURL error: %v", err)
    }
    parsed, err := url.Parse(u)
    if err != nil {
        t.Fatalf("parse result error: %v", err)
    }
    if parsed.Scheme != "http" || parsed.Host != "localhost:8080" || parsed.Path != "/overview" {
        t.Fatalf("unexpected result: %v", u)
    }
    if q := parsed.Query().Get("tag"); q != "dev" {
        t.Fatalf("query mismatch, got %q", q)
    }
}
