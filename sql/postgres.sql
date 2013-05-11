CREATE SCHEMA oauth;

CREATE SEQUENCE s_oauth_access_token_scopes INCREMENT BY 1;
CREATE SEQUENCE s_oauth_access_tokens INCREMENT BY 1;
CREATE SEQUENCE s_oauth_authcodes INCREMENT BY 1;
CREATE SEQUENCE s_oauth_client_endpoints INCREMENT BY 1;
CREATE SEQUENCE s_oauth_scopes INCREMENT BY 1;
CREATE SEQUENCE s_oauth_sessions INCREMENT BY 1;

CREATE TABLE oauth_access_token_scopes
(
  id BIGINT DEFAULT nextval('oauth.s_oauth_access_token_scopes') NOT NULL,
	access_token_id INTEGER NOT NULL,
	scope_id SMALLINT NOT NULL
);
ALTER TABLE oauth_access_token_scopes ADD CONSTRAINT p_oauth_access_token_scopes PRIMARY KEY (id);
CREATE INDEX i_oaactosc_scid ON oauth_access_token_scopes (scope_id);
CREATE UNIQUE INDEX u_oaactosc_actoid_scid ON oauth_access_token_scopes (access_token_id, scope_id);

CREATE TABLE oauth_access_tokens
(
	id INTEGER DEFAULT nextval('oauth.s_oauth_access_tokens') NOT NULL,
	session_id INTEGER NOT NULL,
	access_token CHAR(40) NOT NULL,
	access_token_expires INTEGER NOT NULL
);
ALTER TABLE oauth_access_tokens ADD CONSTRAINT p_oauth_access_tokens PRIMARY KEY (id);
CREATE INDEX i_oaacto_seid ON oauth_access_tokens (session_id);
CREATE UNIQUE INDEX u_oaacto_acto_seid ON oauth_access_tokens (access_token, session_id);

CREATE TABLE oauth_authcode_scopes
(
	authcode_id INTEGER NOT NULL,
	scope_id SMALLINT NOT NULL
);
ALTER TABLE oauth_authcode_scopes ADD CONSTRAINT p_oauth_authcode_scopes PRIMARY KEY (authcode_id, scope_id);
CREATE INDEX i_oaausc_auid ON oauth_authcode_scopes (authcode_id);
CREATE INDEX i_oaausc_scid ON oauth_authcode_scopes (scope_id);

CREATE TABLE oauth_authcodes
(
	id INTEGER DEFAULT nextval('oauth.s_oauth_authcodes') NOT NULL,
	session_id INTEGER NOT NULL,
	auth_code CHAR(40) NOT NULL,
	auth_code_expires INTEGER NOT NULL
);
ALTER TABLE oauth_authcodes ADD CONSTRAINT p_oauth_authcodes PRIMARY KEY (id);
CREATE UNIQUE INDEX u_oaau_seid ON oauth_authcodes (session_id);

CREATE TABLE oauth_client_endpoints
(
	id INTEGER DEFAULT nextval('oauth.s_oauth_client_endpoints') NOT NULL,
	client_id CHAR(40) NOT NULL,
	redirect_uri VARCHAR(255) NOT NULL
);
ALTER TABLE oauth_client_endpoints ADD CONSTRAINT p_oauth_client_endpoints PRIMARY KEY (id);
CREATE INDEX i_oaclen_clid ON oauth_client_endpoints (client_id);

CREATE TABLE oauth_clients
(
	id CHAR(40) NOT NULL,
	secret CHAR(40) NOT NULL,
	name VARCHAR(255) NOT NULL,
	auto_approve SMALLINT DEFAULT 0 NOT NULL
);
ALTER TABLE oauth_clients ADD CONSTRAINT p_oauth_clients PRIMARY KEY (id);
CREATE UNIQUE INDEX u_oacl_se_id ON oauth_clients (secret, id);

CREATE TABLE oauth_redirects
(
	session_id INTEGER NOT NULL,
	redirect_uri VARCHAR(255) NOT NULL
);
ALTER TABLE oauth_redirects ADD CONSTRAINT p_oauth_redirects PRIMARY KEY (session_id);

CREATE TABLE oauth_refresh_tokens
(
	access_token_id INTEGER NOT NULL,
	refresh_token CHAR(40) NOT NULL,
	refresh_token_expires INTEGER NOT NULL
);
ALTER TABLE oauth_refresh_tokens ADD CONSTRAINT p_oauth_refresh_tokens PRIMARY KEY (access_token_id);
CREATE INDEX i_oareto_actoid ON oauth_refresh_tokens (access_token_id);

CREATE TABLE oauth_scopes
(
	id SMALLINT DEFAULT nextval('oauth.s_oauth_scopes') NOT NULL,
	scope VARCHAR(255) NOT NULL,
	name VARCHAR(255) NULL,
	description VARCHAR(255) NULL
);
ALTER TABLE oauth_scopes ADD CONSTRAINT p_oauth_scopes PRIMARY KEY (id);
CREATE UNIQUE INDEX u_oasc_sc ON oauth_scopes (scope);

CREATE TABLE oauth_sessions
(
	id INTEGER DEFAULT nextval('oauth.s_oauth_sessions') NOT NULL,
	client_id CHAR(40) NOT NULL,
	owner_type VARCHAR(6) DEFAULT 'user' NOT NULL,
	owner_id VARCHAR(255) NOT NULL
);
ALTER TABLE oauth_sessions ADD CONSTRAINT p_oauth_sessions PRIMARY KEY (id);
CREATE INDEX i_oase_clid_owty_owid ON oauth_sessions (client_id, owner_type, owner_id);

ALTER TABLE oauth_access_token_scopes ADD CONSTRAINT f_oaactosc_actoid FOREIGN KEY (access_token_id) REFERENCES oauth_access_tokens (id) ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE oauth_access_token_scopes ADD CONSTRAINT f_oaactosc_scid FOREIGN KEY (scope_id) REFERENCES oauth_scopes (id) ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE oauth_access_tokens ADD CONSTRAINT f_oaacto_seid FOREIGN KEY (session_id) REFERENCES oauth_sessions (id) ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE oauth_authcode_scopes ADD CONSTRAINT f_oaausc_auid FOREIGN KEY (authcode_id) REFERENCES oauth_authcodes (id) ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE oauth_authcode_scopes ADD CONSTRAINT f_oaausc_scid FOREIGN KEY (scope_id) REFERENCES oauth_scopes (id) ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE oauth_authcodes ADD CONSTRAINT f_oaau_seid FOREIGN KEY (session_id) REFERENCES oauth_sessions (id) ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE oauth_client_endpoints ADD CONSTRAINT f_oaclen_clid FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON UPDATE CASCADE ON DELETE CASCADE;
ALTER TABLE oauth_redirects ADD CONSTRAINT f_oare_seid FOREIGN KEY (session_id) REFERENCES oauth_sessions (id) ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE oauth_refresh_tokens ADD CONSTRAINT f_oareto_actoid FOREIGN KEY (access_token_id) REFERENCES oauth_access_tokens (id) ON UPDATE NO ACTION ON DELETE CASCADE;
ALTER TABLE oauth_sessions ADD CONSTRAINT f_oase_clid FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON UPDATE CASCADE ON DELETE CASCADE;
