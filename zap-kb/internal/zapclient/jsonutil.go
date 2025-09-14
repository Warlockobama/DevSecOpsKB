package zapclient

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Intish accepts JSON numbers OR numeric strings (or ""), storing as int.
type Intish int

func (i *Intish) UnmarshalJSON(b []byte) error {
	// null -> 0
	if string(b) == "null" {
		*i = 0
		return nil
	}
	// Try as number first
	var num json.Number
	if err := json.Unmarshal(b, &num); err == nil {
		if num == "" {
			*i = 0
			return nil
		}
		n, err := num.Int64()
		if err != nil {
			*i = 0
			return nil
		}
		*i = Intish(n)
		return nil
	}
	// Fall back to plain string
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		*i = 0
		return nil
	}
	s = strings.TrimSpace(s)
	if s == "" {
		*i = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		*i = 0
		return nil
	}
	*i = Intish(n)
	return nil
}

func (i Intish) Int() int { return int(i) }
