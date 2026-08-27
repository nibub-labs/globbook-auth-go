package globbookauth

import (
	"errors"
	"net/url"
	"testing"
)

func TestParseCallbackParams_ParsesCode(t *testing.T) {
	values := url.Values{}
	values.Set("code", "code-value")

	got, err := ParseCallbackParams(values)
	if err != nil {
		t.Fatalf("ParseCallbackParams() unexpected error: %v", err)
	}
	if got != "code-value" {
		t.Errorf("ParseCallbackParams() = %q, want %q", got, "code-value")
	}
}

func TestParseCallbackParams_ReturnsErrorWhenParamNotPresent(t *testing.T) {
	values := url.Values{}
	values.Set("some_other_param", "value")

	_, err := ParseCallbackParams(values)
	if !errors.Is(err, ErrMissingCallbackCode) {
		t.Errorf("ParseCallbackParams() error = %v, want ErrMissingCallbackCode", err)
	}
}

func TestParseCallbackParams_EmptyValues(t *testing.T) {
	_, err := ParseCallbackParams(url.Values{})
	if !errors.Is(err, ErrMissingCallbackCode) {
		t.Errorf("ParseCallbackParams() error = %v, want ErrMissingCallbackCode", err)
	}
}

func TestParseCallbackParams_EmptyStringCodeReturnsError(t *testing.T) {
	values := url.Values{}
	values.Set("code", "")

	_, err := ParseCallbackParams(values)
	if !errors.Is(err, ErrMissingCallbackCode) {
		t.Errorf("ParseCallbackParams() error = %v, want ErrMissingCallbackCode", err)
	}
}
