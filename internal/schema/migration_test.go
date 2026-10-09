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
			var n int
			if err := db.QueryRow("SELECT COUNT(*) FROM traffic_1m").Scan(&n); err != nil || n != 0 {
				t.Fatal("legacy traffic retained", n, err)
			}
			var columns int
			if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('agents') WHERE name='pending_from'").Scan(&columns); err != nil || columns != 1 {
				t.Fatalf("confirmation field: %d %v", columns, err)
			}
			if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('agents') WHERE name='assigned_through'").Scan(&columns); err != nil || columns != 1 {
				t.Fatalf("assigned high water: %d %v", columns, err)
			}
		})
	}
}

func TestServiceMigrationPreservesDecisions(t *testing.T) {
	db := openTestDB(t)
	if err := ApplyMonitor(db); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"PRAGMA user_version=15",
		"INSERT INTO settings(k,v) VALUES('samples_n','30'),('db_max_gb','2'),('adm_password','keep'),('cf','old')",
		"INSERT INTO policy_rules VALUES('keep',1,1,'{}')",
		"INSERT INTO blocks(block_id,scope_kind,state,reason,source,created_by,created_at_ms) VALUES('keep','all','active','manual','manual','adm',1)",
		"INSERT INTO hosts(host_id) VALUES('h')",
		"INSERT INTO learn_questions(question_id,host_id,dedup_key,opened_at_ms,last_seen_ms,repeats,direction,protocol,remote_ip,status) VALUES('keep','h','key',1,2,4,'out','tcp','1.1.1.1','open')",
		"INSERT INTO traffic_1m VALUES('h',1,'out','internet',1,2,3)",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := ApplyMonitor(db); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"policy_rules", "blocks", "learn_questions"} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 1 {
			t.Fatal(table, n, err)
		}
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM traffic_1m").Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	var mb, pw string
	if err := db.QueryRow("SELECT v FROM settings WHERE k='db_max_mb'").Scan(&mb); err != nil || mb != "2048" {
		t.Fatal(mb, err)
	}
	if err := db.QueryRow("SELECT v FROM settings WHERE k='adm_password'").Scan(&pw); err != nil || pw != "keep" {
		t.Fatal(pw, err)
	}
}
