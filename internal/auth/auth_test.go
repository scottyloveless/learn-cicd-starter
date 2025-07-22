package auth

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
)

func TestAPIkey(t *testing.T) {
	tests := map[string]struct {
		header  http.Header
		want    string
		wanterr error
	}{
		"empty header":              {header: http.Header{}, want: "", wanterr: fmt.Errorf("no authorization header included")},
		"valid header":              {header: http.Header{"Authorization": []string{"ApiKey randomkey"}}, want: "randomkey", wanterr: nil},
		"no auth key":               {header: http.Header{"Authorization": []string{"ApiKey "}}, want: "", wanterr: fmt.Errorf("malformed authorization header")},
		"double space after apikey": {header: http.Header{"Authorization": []string{"ApiKey  "}}, want: "", wanterr: fmt.Errorf("malformed authorization header")},
		"no apikey key":             {header: http.Header{"Authorization": []string{"AApiikey randomkey"}}, want: "", wanterr: fmt.Errorf("malformed authorization header")},
	}

	for name, tc := range tests {
		got, _ := GetAPIKey(tc.header)
		if !reflect.DeepEqual(tc.want, got) {
			t.Fatalf("%s: expected: %v, got: %v, wanterr: %v", name, tc.want, got, tc.wanterr)
		}
	}
}
