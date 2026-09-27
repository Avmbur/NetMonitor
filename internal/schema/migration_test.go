package schema

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMigrationsPreserveLegacyData(t *testing.T) {
	for _, agent := range []bool{false, true} {
		for _, oldVersion := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("agent=%t/version=%d", agent, oldVersion), func(t *testing.T) {
				db := openTestDB(t)
				script, migrate, table, id := MonitorSQL, ApplyMonitor, "settings", monitorID
				if agent {
					script, migrate, table, id = AgentSQL, ApplyAgent, "meta", agentID
				}
				// Version 0 models an interrupted legacy installation.
				if _, err := db.Exec(script); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version=%d", oldVersion)); err != nil {
					t.Fatal(err)
				}
				if oldVersion == 2 {
					if _, err := db.Exec(`CREATE TABLE block_pause(agent_id TEXT, block_id TEXT, paused_at_ms INTEGER, PRIMARY KEY(agent_id,block_id))`); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := db.Exec("INSERT INTO " + table + "(k,v) VALUES('keep','original')"); err != nil {
					t.Fatal(err)
				}
				for attempt := 0; attempt < 2; attempt++ {
					if err := migrate(db); err != nil {
						t.Fatal(err)
					}
				}
				var value string
				if err := db.QueryRow("SELECT v FROM " + table + " WHERE k='keep'").Scan(&value); err != nil || value != "original" {
					t.Fatalf("data lost: %q %v", value, err)
				}
				var gotID, gotVersion int
				if err := db.QueryRow("PRAGMA application_id").Scan(&gotID); err != nil {
					t.Fatal(err)
				}
				if err := db.QueryRow("PRAGMA user_version").Scan(&gotVersion); err != nil {
					t.Fatal(err)
				}
				wantVersion := version
				if agent {
					wantVersion = agentVersion
				}
				if gotID != id || gotVersion != wantVersion {
					t.Fatalf("identity=%d version=%d", gotID, gotVersion)
				}
				if agent && oldVersion < 2 {
					var n int
					if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='block_pause'`).Scan(&n); err != nil {
						t.Fatal(err)
					}
					if n != 0 {
						t.Fatal("monitor migration ran on agent")
					}
				}
			})
		}
	}
}

func TestMigrationFailureIsAtomic(t *testing.T) {
	db := openTestDB(t)
	bad := MonitorSQL + "\nCREATE TABLE broken(;"
	if err := apply(db, bad, monitorID, "hosts", "meta"); err == nil {
		t.Fatal("expected invalid migration")
	}
	var n, ver int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil {
		t.Fatal(err)
	}
	if n != 0 || ver != 0 {
		t.Fatalf("partial migration: tables=%d version=%d", n, ver)
	}
	if err := ApplyMonitor(db); err != nil {
		t.Fatal(err)
	}
	if err := ApplyAgent(db); err == nil {
		t.Fatal("accepted wrong database kind")
	}
	if _, err := db.Exec("PRAGMA user_version=999"); err != nil {
		t.Fatal(err)
	}
	if err := ApplyMonitor(db); err == nil {
		t.Fatal("accepted future schema")
	}
}

func TestQueueConfirmationMigration(t *testing.T) {
	for _, v := range []int{6, 7, 8} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			db := openTestDB(t)
			if _, err := db.Exec(MonitorSQL); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("INSERT INTO traffic_1m VALUES('h',1000,'out','internet',100,200,3)"); err != nil {
				t.Fatal(err)
			}
			if v == 8 {
				if _, err := db.Exec("ALTER TABLE agents ADD COLUMN pending_from INTEGER NOT NULL DEFAULT 1"); err != nil {
					t.Fatal(err)
				}
			}
			if v == 7 {
				if _, err := db.Exec("ALTER TABLE traffic_1m ADD COLUMN archive_generation TEXT NOT NULL DEFAULT ''"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version=%d", v)); err != nil {
				t.Fatal(err)
			}
			if err := ApplyMonitor(db); err != nil {
				t.Fatal(err)
			}
			if err := ApplyMonitor(db); err != nil {
				t.Fatal(err)
			}
			var out, in, n int
			if err := db.QueryRow("SELECT bytes_out,bytes_in,samples FROM traffic_1m").Scan(&out, &in, &n); err != nil {
				t.Fatal(err)
			}
			if out != 100 || in != 200 || n != 3 {
				t.Fatalf("data lost: %d/%d/%d", out, in, n)
			}
			var columns int
			if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('agents') WHERE name='pending_from'").Scan(&columns); err != nil || columns != 1 {
				t.Fatalf("confirmation field: %d %v", columns, err)
			}
		})
	}
}
