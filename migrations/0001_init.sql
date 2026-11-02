-- 0001_init.sql (dihasilkan oleh scripts/gen_ddl.py dari services/common/models.py untuk PostgreSQL)

CREATE TABLE analyses (
	event_id VARCHAR(36) NOT NULL, 
	tenant_id VARCHAR(64) NOT NULL, 
	status VARCHAR(24) NOT NULL, 
	result JSON NOT NULL, 
	sources JSON NOT NULL, 
	model VARCHAR(128), 
	prompt_version VARCHAR(32), 
	attempts INTEGER NOT NULL, 
	next_attempt_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	error TEXT, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (event_id)
);

CREATE INDEX ix_analyses_status ON analyses (status);

CREATE INDEX ix_analyses_tenant_id ON analyses (tenant_id);

CREATE TABLE audit_log (
	id SERIAL NOT NULL, 
	tenant_id VARCHAR(64) NOT NULL, 
	actor VARCHAR(128) NOT NULL, 
	role VARCHAR(16) NOT NULL, 
	action VARCHAR(64) NOT NULL, 
	target VARCHAR(128) NOT NULL, 
	detail JSON NOT NULL, 
	ts TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX ix_audit_log_action ON audit_log (action);

CREATE INDEX ix_audit_log_ts ON audit_log (ts);

CREATE INDEX ix_audit_log_tenant_id ON audit_log (tenant_id);

CREATE TABLE cases (
	case_id VARCHAR(36) NOT NULL, 
	tenant_id VARCHAR(64) NOT NULL, 
	title VARCHAR(256) NOT NULL, 
	description TEXT NOT NULL, 
	status VARCHAR(16) NOT NULL, 
	priority VARCHAR(8) NOT NULL, 
	assignee VARCHAR(128), 
	created_by VARCHAR(128) NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (case_id)
);

CREATE INDEX ix_cases_status ON cases (status);

CREATE INDEX ix_cases_tenant_id ON cases (tenant_id);

CREATE TABLE connector_state (
	name VARCHAR(64) NOT NULL, 
	tenant_id VARCHAR(64) NOT NULL, 
	type VARCHAR(32) NOT NULL, 
	cursor VARCHAR(256), 
	last_success TIMESTAMP WITHOUT TIME ZONE, 
	last_error TEXT, 
	last_warning TEXT, 
	consecutive_failures INTEGER NOT NULL, 
	events_total INTEGER NOT NULL, 
	rejected_total INTEGER NOT NULL, 
	mapping_version VARCHAR(32) NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (name)
);

CREATE TABLE events (
	event_id VARCHAR(36) NOT NULL, 
	tenant_id VARCHAR(64) NOT NULL, 
	source VARCHAR(64) NOT NULL, 
	source_event_id VARCHAR(128) NOT NULL, 
	event_time TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	received_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	severity VARCHAR(16) NOT NULL, 
	attack_type VARCHAR(48) NOT NULL, 
	signature VARCHAR(256) NOT NULL, 
	src_ip VARCHAR(64), 
	dst_ip VARCHAR(64), 
	dst_port INTEGER, 
	protocol VARCHAR(16), 
	host VARCHAR(128), 
	username VARCHAR(128), 
	entities JSON NOT NULL, 
	technique_id VARCHAR(16), 
	tactic VARCHAR(48), 
	triplet_key VARCHAR(300) NOT NULL, 
	message TEXT NOT NULL, 
	payload JSON NOT NULL, 
	processing_status VARCHAR(16) NOT NULL, 
	analysis_status VARCHAR(24) NOT NULL, 
	disposition VARCHAR(16) NOT NULL, 
	disposition_reason TEXT NOT NULL, 
	noise_info JSON NOT NULL, 
	orchestration JSON NOT NULL, 
	risk_score FLOAT, 
	risk_level VARCHAR(8), 
	scoring_version VARCHAR(32), 
	score_components JSON NOT NULL, 
	graph_snapshot_id VARCHAR(32), 
	integrity JSON NOT NULL, 
	enrichment_status VARCHAR(16) NOT NULL, 
	PRIMARY KEY (event_id), 
	CONSTRAINT uq_event_dedupe UNIQUE (tenant_id, source, source_event_id)
);

CREATE INDEX ix_events_triplet_key ON events (triplet_key);

CREATE INDEX ix_events_host ON events (host);

CREATE INDEX ix_events_tenant_id ON events (tenant_id);

CREATE INDEX ix_events_attack_type ON events (attack_type);

CREATE INDEX ix_events_src_ip ON events (src_ip);

CREATE INDEX ix_events_dst_ip ON events (dst_ip);

CREATE INDEX ix_events_risk_score ON events (risk_score);

CREATE INDEX ix_events_processing_status ON events (processing_status);

CREATE INDEX ix_events_tenant_time ON events (tenant_id, event_time);

CREATE INDEX ix_events_technique_id ON events (technique_id);

CREATE INDEX ix_events_risk_level ON events (risk_level);

CREATE INDEX ix_events_event_time ON events (event_time);

CREATE INDEX ix_events_disposition ON events (disposition);

CREATE TABLE kb_candidates (
	id SERIAL NOT NULL, 
	tenant_id VARCHAR(64) NOT NULL, 
	event_id VARCHAR(36) NOT NULL, 
	hypothesis TEXT NOT NULL, 
	evidence JSON NOT NULL, 
	confidence FLOAT NOT NULL, 
	status VARCHAR(12) NOT NULL, 
	reviewed_by VARCHAR(128), 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX ix_kb_candidates_tenant_id ON kb_candidates (tenant_id);

CREATE TABLE kb_items (
	item_id VARCHAR(64) NOT NULL, 
	kind VARCHAR(16) NOT NULL, 
	data JSON NOT NULL, 
	source VARCHAR(64) NOT NULL, 
	version VARCHAR(64) NOT NULL, 
	checksum VARCHAR(64) NOT NULL, 
	updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (item_id)
);

CREATE INDEX ix_kb_items_kind ON kb_items (kind);

CREATE TABLE kb_runs (
	id SERIAL NOT NULL, 
	started_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	finished_at TIMESTAMP WITHOUT TIME ZONE, 
	status VARCHAR(12) NOT NULL, 
	source VARCHAR(64) NOT NULL, 
	version VARCHAR(64) NOT NULL, 
	added INTEGER NOT NULL, 
	updated INTEGER NOT NULL, 
	unchanged INTEGER NOT NULL, 
	error TEXT, 
	previous_snapshot JSON NOT NULL, 
	PRIMARY KEY (id)
);

CREATE TABLE leases (
	name VARCHAR(64) NOT NULL, 
	holder VARCHAR(128) NOT NULL, 
	expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (name)
);

CREATE TABLE outbox (
	id SERIAL NOT NULL, 
	event_id VARCHAR(36) NOT NULL, 
	kind VARCHAR(24) NOT NULL, 
	status VARCHAR(12) NOT NULL, 
	attempts INTEGER NOT NULL, 
	next_attempt_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	last_error TEXT, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id)
);

CREATE INDEX ix_outbox_event_id ON outbox (event_id);

CREATE INDEX ix_outbox_status ON outbox (status);

CREATE TABLE policy_state (
	id INTEGER NOT NULL, 
	version INTEGER NOT NULL, 
	policy JSON NOT NULL, 
	signature TEXT NOT NULL, 
	issued_at VARCHAR(32) NOT NULL, 
	applied_at TIMESTAMP WITHOUT TIME ZONE, 
	last_check TIMESTAMP WITHOUT TIME ZONE, 
	last_error TEXT, 
	PRIMARY KEY (id)
);

CREATE TABLE triplet_counts (
	tenant_id VARCHAR(64) NOT NULL, 
	triplet_key VARCHAR(300) NOT NULL, 
	hour TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	count INTEGER NOT NULL, 
	PRIMARY KEY (tenant_id, triplet_key, hour)
);

CREATE TABLE triplet_state (
	tenant_id VARCHAR(64) NOT NULL, 
	triplet_key VARCHAR(300) NOT NULL, 
	evaluated_at TIMESTAMP WITHOUT TIME ZONE, 
	result JSON NOT NULL, 
	PRIMARY KEY (tenant_id, triplet_key)
);

CREATE TABLE case_alerts (
	case_id VARCHAR(36) NOT NULL, 
	event_id VARCHAR(36) NOT NULL, 
	linked_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (case_id, event_id), 
	FOREIGN KEY(case_id) REFERENCES cases (case_id)
);

CREATE TABLE case_notes (
	id SERIAL NOT NULL, 
	case_id VARCHAR(36) NOT NULL, 
	author VARCHAR(128) NOT NULL, 
	text TEXT NOT NULL, 
	created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(case_id) REFERENCES cases (case_id)
);

CREATE INDEX ix_case_notes_case_id ON case_notes (case_id);
