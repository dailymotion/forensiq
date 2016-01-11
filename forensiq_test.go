package forensiq

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"golang.org/x/net/context"
)

func TestReady(t *testing.T) {
	tests := map[string]bool{
		"1": true,
		"0": false,
	}

	for b, want := range tests {
		m := http.NewServeMux()
		m.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(b))
		})
		ts := httptest.NewServer(m)
		defer ts.Close()

		f := &Forensiq{ClientKey: "123abc", Host: ts.URL}
		ready, err := f.Ready(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got := ready; want != got {
			t.Errorf("f.Ready: want %t got %t", want, got)
		}
	}
}

func TestCheck(t *testing.T) {
	m := http.NewServeMux()
	m.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("ck") == "" {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		if q.Get("output") != "JSON" {
			http.Error(w, "output=JSON is required", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"nonSuspect":true,"riskScore":0,"timeMs":10}`))
	})
	ts := httptest.NewServer(m)
	f := &Forensiq{Host: ts.URL}

	_, err := f.Check(context.Background(), CheckRequest{})
	if want, got := ErrInvalidClientKey, err; want.Error() != got.Error() {
		t.Errorf("f.Check() error: want %s got %s", want, got)
	}

	f.ClientKey = "123abc"
	cresp, err := f.Check(context.Background(), CheckRequest{})
	if err != nil {
		t.Fatal(err)
	}

	want := CheckResponse{NonSuspect: true, RiskScore: 0, TimeMS: 10}
	if !reflect.DeepEqual(want, cresp) {
		t.Errorf("f.Check: want %v got %v", want, cresp)
	}
}
