package validate

import (
	"fmt"
	"strings"

	"github.com/piekstra/newrelic-cli/api"
)

// Region validates New Relic region (US or EU)
func Region(region string) error {
	upper := strings.ToUpper(region)
	if upper != "US" && upper != "EU" {
		return fmt.Errorf("invalid region %q: must be US or EU", region)
	}
	return nil
}

// AccountID validates account ID is numeric and positive
func AccountID(id string) error {
	_, err := api.NewAccountID(id)
	return err
}

// APIKey validates API key format
// Returns warning message (not error) for non-standard formats
func APIKey(key string) (warning string, err error) {
	_, warning, err = api.NewAPIKey(key)
	return warning, err
}
