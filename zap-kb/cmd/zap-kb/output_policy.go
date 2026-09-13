package main

import (
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"strings"
)

func validateForgejoRedact(list string) error {
	if v := strings.ToLower(strings.TrimSpace(list)); v == "off" || v == "none" {
		return nil
	}
	_, err := entities.ParseRedactOptions(list)
	return err
}

func mergeRedactOptions(a, b entities.RedactOptions) entities.RedactOptions {
	return entities.RedactOptions{Domain: a.Domain || b.Domain, Query: a.Query || b.Query, Cookies: a.Cookies || b.Cookies, Auth: a.Auth || b.Auth, Headers: a.Headers || b.Headers, Body: a.Body || b.Body, Notes: a.Notes || b.Notes, Secrets: a.Secrets || b.Secrets}
}
