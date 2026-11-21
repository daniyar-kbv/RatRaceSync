CREATE TABLE meta (name TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
CREATE TABLE raft_log (idx BLOB PRIMARY KEY CHECK(length(idx)=8), entry BLOB NOT NULL) STRICT;
CREATE TABLE archive (idx BLOB PRIMARY KEY, log_id BLOB UNIQUE NOT NULL, source BLOB NOT NULL,
    digest BLOB NOT NULL, event_count INTEGER NOT NULL, event_tip BLOB NOT NULL,
    receipt_count INTEGER NOT NULL, receipt_tip BLOB NOT NULL) STRICT;
CREATE TABLE event (seq INTEGER PRIMARY KEY, actor BLOB NOT NULL, position BLOB NOT NULL,
    cash_after TEXT NOT NULL, units_after TEXT NOT NULL, record BLOB NOT NULL, digest BLOB NOT NULL, tip BLOB NOT NULL) STRICT;
CREATE INDEX event_cash ON event(actor,seq);
CREATE INDEX event_units ON event(actor,position,seq);
CREATE TABLE receipt (seq INTEGER PRIMARY KEY, actor BLOB NOT NULL, request BLOB NOT NULL,
    fingerprint BLOB NOT NULL, record BLOB NOT NULL, tip BLOB NOT NULL, UNIQUE(actor,request)) STRICT;
-- Fixed participants and opening positions are supplied by committed game setup.
CREATE TABLE participant (actor BLOB PRIMARY KEY, key BLOB NOT NULL UNIQUE, node BLOB UNIQUE NOT NULL CHECK(length(node)=16), opening_cash TEXT NOT NULL,cash TEXT NOT NULL,
    monthly TEXT NOT NULL) STRICT;
CREATE TABLE certificate (actor BLOB NOT NULL REFERENCES participant(actor), position BLOB NOT NULL,
    principal INTEGER NOT NULL CHECK(principal IN (4000,5000)), opening_units TEXT NOT NULL,units TEXT NOT NULL,
    PRIMARY KEY(actor,position)) STRICT;
