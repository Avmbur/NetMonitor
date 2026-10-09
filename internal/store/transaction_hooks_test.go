package store

import (
	"database/sql"
	"errors"
	"testing"
)

func TestTransactionHooksFollowSavepointAndCommit(t *testing.T) {
	st, err := OpenMonitor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var got []bool
	if err := st.Update(func(tx *sql.Tx) error {
		OnFinish(tx, func(ok bool) { got = append(got, ok) })
		mark := HookMark(tx)
		if _, err := tx.Exec("SAVEPOINT probe"); err != nil {
			return err
		}
		OnFinish(tx, func(ok bool) { got = append(got, ok) })
		if _, err := tx.Exec("ROLLBACK TO probe"); err != nil {
			return err
		}
		RollbackHooks(tx, mark)
		_, err := tx.Exec("RELEASE probe")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] || !got[1] {
		t.Fatal(got)
	}
	got = nil
	abort := errors.New("abort")
	if err := st.Update(func(tx *sql.Tx) error { OnFinish(tx, func(ok bool) { got = append(got, ok) }); return abort }); !errors.Is(err, abort) {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] {
		t.Fatal(got)
	}
}
