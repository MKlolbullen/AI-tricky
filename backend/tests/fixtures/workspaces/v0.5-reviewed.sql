-- Synthetic SQLite dump written with AI-tricky v0.5.0 (2bd0a3f).
BEGIN TRANSACTION;
CREATE TABLE artifacts(id TEXT PRIMARY KEY, run_id TEXT NOT NULL, name TEXT NOT NULL, content TEXT NOT NULL, node_id TEXT, captured_at TEXT);
INSERT INTO "artifacts" VALUES('5a2d4896-698d-4440-93ce-437efbca3776','9a044a06-e897-4bfe-a570-89b10c8485b0','http-1.json','{"url": "https://fixture.invalid/example", "status": 200, "headers": {}, "body": "Synthetic release fixture."}',NULL,'2026-11-23T15:51:37.228062+00:00');
INSERT INTO "artifacts" VALUES('b509fb7c-c2a0-498a-8440-193eb9a4de0f','9a044a06-e897-4bfe-a570-89b10c8485b0','node-review.json','[{"analysis": {"candidates": [{"title": "Synthetic review example", "severity": "low", "rationale": "Fixture for data preservation.", "evidence_ids": ["5a2d4896-698d-4440-93ce-437efbca3776"]}]}}]',NULL,'2026-11-23T15:51:37.228328+00:00');
CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, time TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE evidence_index(
                artifact_id TEXT NOT NULL, parser_version TEXT NOT NULL, report TEXT NOT NULL,
                PRIMARY KEY(artifact_id,parser_version));
INSERT INTO "evidence_index" VALUES('5a2d4896-698d-4440-93ce-437efbca3776','1','{"parser_version":"1","partial":false,"supported":true}');
INSERT INTO "evidence_index" VALUES('b509fb7c-c2a0-498a-8440-193eb9a4de0f','1','{"parsed_records":1,"parser_version":"1","supported":true}');
CREATE TABLE finding_occurrences(
                finding_id TEXT NOT NULL, observation_id TEXT NOT NULL UNIQUE, run_id TEXT NOT NULL,
                evidence_ids TEXT NOT NULL, snapshot TEXT NOT NULL,
                PRIMARY KEY(finding_id,observation_id));
INSERT INTO "finding_occurrences" VALUES('7bd711bd-90c0-4625-a22a-b4a73ec338ac','d538b979-b073-4bb1-b5c8-8f9665b0c51e','9a044a06-e897-4bfe-a570-89b10c8485b0','["b509fb7c-c2a0-498a-8440-193eb9a4de0f","5a2d4896-698d-4440-93ce-437efbca3776"]','{"assets":["https://fixture.invalid/example"],"next_test":"","rationale":"Fixture for data preservation.","severity":"low","title":"Synthetic review example"}');
CREATE TABLE finding_reviews(
                id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, created TEXT NOT NULL,
                revision INTEGER NOT NULL, previous TEXT NOT NULL, decision TEXT NOT NULL,
                note TEXT NOT NULL, evidence_id TEXT, UNIQUE(finding_id,revision));
INSERT INTO "finding_reviews" VALUES('284a1e17-ef1c-4879-be12-44dc23b46df4','7bd711bd-90c0-4625-a22a-b4a73ec338ac','2026-11-23T15:51:37.238573+00:00',2,'{"confidence":"unknown","severity":"low","status":"candidate"}','{"confidence":"high","severity":"info","status":"verified"}','Checked the saved fixture response.','5a2d4896-698d-4440-93ce-437efbca3776');
CREATE TABLE findings(
                id TEXT PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL, asset TEXT NOT NULL,
                source TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
                confidence TEXT NOT NULL, status TEXT NOT NULL, rationale TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, revision INTEGER NOT NULL);
INSERT INTO "findings" VALUES('7bd711bd-90c0-4625-a22a-b4a73ec338ac','a3e516b0547e77d52e0410b808096172286b5e32f441b15c5346cb30d5449ec4','https://fixture.invalid/example','cai-evidence','Synthetic review example','info','high','verified','Fixture for data preservation.','2026-11-23T15:51:37.228328+00:00','2026-11-23T15:51:37.228328+00:00',2);
CREATE TABLE inputs(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,path TEXT NOT NULL,sha256 TEXT,created TEXT NOT NULL);
CREATE TABLE observations(
                id TEXT PRIMARY KEY, run_id TEXT NOT NULL, node_id TEXT, artifact_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL, value_hash TEXT NOT NULL, kind TEXT NOT NULL,
                asset TEXT NOT NULL, source TEXT NOT NULL, parser_version TEXT NOT NULL,
                data TEXT NOT NULL, observed_at TEXT NOT NULL,
                UNIQUE(artifact_id,fingerprint,value_hash));
INSERT INTO "observations" VALUES('7bc8c383-c9a0-4677-9f0c-79ab1c7eb515','9a044a06-e897-4bfe-a570-89b10c8485b0',NULL,'5a2d4896-698d-4440-93ce-437efbca3776','8a00f132da51f5c2eebcc6b45a9dd9a083e60e78bdbaba3a69f9193963a3cf0b','ca26f856f76f667cb537660eb8aa32df3e8680197cb16525bd623902151f9565','http','https://fixture.invalid/example','native-http','1','{"body_sha256":"695afc457a6940ebb69904f8c80215cab299ba475c91a4fe23560138f4c9ff76","body_truncated":false,"headers":{},"status":200}','2026-11-23T15:51:37.228062+00:00');
INSERT INTO "observations" VALUES('d538b979-b073-4bb1-b5c8-8f9665b0c51e','9a044a06-e897-4bfe-a570-89b10c8485b0',NULL,'b509fb7c-c2a0-498a-8440-193eb9a4de0f','62c83962e9099f749d1c3c41c2ddbe6d8cfbfec9a04bbf8745dbb28c235b39e1','29a4f40af982d1d2e42e6d34a8c705b173fc5e335580135416ab8acde2040b75','detection','https://fixture.invalid/example','cai-evidence','1','{"assets":["https://fixture.invalid/example"],"next_test":"","rationale":"Fixture for data preservation.","severity":"low","title":"Synthetic review example"}','2026-11-23T15:51:37.228328+00:00');
CREATE TABLE run_nodes(run_id TEXT NOT NULL, node_id TEXT NOT NULL, status TEXT NOT NULL, updated TEXT NOT NULL, result TEXT, PRIMARY KEY(run_id,node_id));
CREATE TABLE runs(id TEXT PRIMARY KEY, status TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL, config TEXT NOT NULL, result TEXT);
INSERT INTO "runs" VALUES('9a044a06-e897-4bfe-a570-89b10c8485b0','completed','2026-11-23T15:51:37.227393+00:00','2026-11-23T15:51:37.228801+00:00','{"engine": "inventory", "targets": ["https://fixture.invalid/"], "allow_http": false}',NULL);
CREATE TABLE targets(id TEXT PRIMARY KEY, url TEXT UNIQUE NOT NULL, created TEXT NOT NULL);
CREATE TABLE workflows(id TEXT PRIMARY KEY, name TEXT NOT NULL, graph TEXT NOT NULL, revision INTEGER NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL);
CREATE INDEX events_by_run ON events(run_id,seq);
CREATE INDEX observations_by_run ON observations(run_id,fingerprint);
CREATE INDEX observations_by_asset ON observations(asset,kind);
CREATE INDEX occurrences_by_run ON finding_occurrences(run_id,finding_id);
DELETE FROM "sqlite_sequence";
COMMIT;
