PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;

CREATE TABLE meta(
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL);

CREATE TABLE checkpoints(
 flow_key TEXT PRIMARY KEY,
 payload TEXT NOT NULL);

CREATE TABLE outbox(
  event_id TEXT PRIMARY KEY,
  seq INTEGER NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  lane TEXT NOT NULL DEFAULT 'history',
  payload TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0);

CREATE TABLE local_policy(
  object_key TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  desired_rev INTEGER NOT NULL,
  applied_at_ms INTEGER NOT NULL);

CREATE TABLE local_questions(
  question_id TEXT PRIMARY KEY,
  created_at_ms INTEGER NOT NULL,
  payload TEXT NOT NULL,
  repeats INTEGER NOT NULL DEFAULT 1,
  sent INTEGER NOT NULL DEFAULT 0);

CREATE INDEX outbox_lane ON outbox(lane,seq);

-- Constant-time accounting of the bounded spool.
CREATE TRIGGER outbox_size_add AFTER INSERT ON outbox BEGIN
 INSERT INTO meta(k,v) VALUES('queue_bytes',CAST(length(CAST(NEW.payload AS BLOB))+256 AS TEXT))
 ON CONFLICT(k) DO UPDATE SET v=CAST(CAST(v AS INTEGER)+length(CAST(NEW.payload AS BLOB))+256 AS TEXT);
END;
CREATE TRIGGER outbox_size_del AFTER DELETE ON outbox BEGIN
 UPDATE meta SET v=CAST(MAX(0,CAST(v AS INTEGER)-length(CAST(OLD.payload AS BLOB))-256) AS TEXT) WHERE k='queue_bytes';
END;
