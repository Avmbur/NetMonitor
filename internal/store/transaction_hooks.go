package store

import (
	"database/sql"
	"sync"
)

// Finish callbacks run on the writer after COMMIT or ROLLBACK, before another
// queued write. They may publish memory, but must not submit database writes.
var txHooks = struct {
	sync.Mutex
	entries map[*sql.Tx][]func(bool)
}{entries: make(map[*sql.Tx][]func(bool))}

func OnFinish(tx *sql.Tx, fn func(bool)) {
	txHooks.Lock()
	txHooks.entries[tx] = append(txHooks.entries[tx], fn)
	txHooks.Unlock()
}

func finishTransaction(tx *sql.Tx, committed bool) {
	txHooks.Lock()
	hooks := txHooks.entries[tx]
	delete(txHooks.entries, tx)
	txHooks.Unlock()
	for _, fn := range hooks {
		fn(committed)
	}
}

// HookMark and RollbackHooks mirror a SQL savepoint in the writer transaction.
func HookMark(tx *sql.Tx) int {
	txHooks.Lock()
	defer txHooks.Unlock()
	return len(txHooks.entries[tx])
}
func RollbackHooks(tx *sql.Tx, mark int) {
	txHooks.Lock()
	hooks := txHooks.entries[tx]
	removed := append([]func(bool){}, hooks[mark:]...)
	txHooks.entries[tx] = hooks[:mark]
	txHooks.Unlock()
	for _, fn := range removed {
		fn(false)
	}
}
