package server

import "database/sql"

// A UI snapshot is all-or-error. Any query, row conversion or iteration failure
// rejects the snapshot instead of replacing a working screen with empty data.
type checkedRead struct {
	db  *sql.DB
	err error
}

func (d *checkedRead) record(e error) error {
	if d.err == nil && e != nil {
		d.err = e
	}
	return e
}

type checkedRows struct {
	*sql.Rows
	d *checkedRead
}

func (r *checkedRows) Scan(dst ...any) error { return r.d.record(r.Rows.Scan(dst...)) }
func (r *checkedRows) Close() error          { r.d.record(r.Rows.Err()); return r.d.record(r.Rows.Close()) }

type checkedRow struct {
	r *sql.Row
	d *checkedRead
}

func (r *checkedRow) Scan(dst ...any) error { return r.d.record(r.r.Scan(dst...)) }
func (d *checkedRead) Query(q string, args ...any) (*checkedRows, error) {
	r, e := d.db.Query(q, args...)
	d.record(e)
	if e != nil {
		return nil, e
	}
	return &checkedRows{r, d}, nil
}
func (d *checkedRead) QueryRow(q string, args ...any) *checkedRow {
	return &checkedRow{d.db.QueryRow(q, args...), d}
}
func (d *checkedRead) setting(key string) string {
	var v string
	e := d.db.QueryRow("SELECT v FROM settings WHERE k=?", key).Scan(&v)
	if e != sql.ErrNoRows {
		d.record(e)
	}
	return v
}
