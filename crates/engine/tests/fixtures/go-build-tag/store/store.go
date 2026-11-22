// Package store searches a tenant's rows. It stands in for a store whose
// full-text search is built in only with the sqlite_fts5 build tag.
package store

// Row is one tenant's row.
type Row struct {
	Tenant string
	Text   string
}

var rows = []Row{{Tenant: "a", Text: "alpha"}, {Tenant: "b", Text: "beta"}}

// Search returns the rows of tenant that hold query. It ignores the tenant:
// the hole the exploit shows.
func Search(tenant, query string) []Row {
	var found []Row
	for _, row := range rows {
		if query == "" || row.Text == query {
			found = append(found, row)
		}
	}
	return found
}
