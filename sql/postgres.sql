START TRANSACTION;
SET standard_conforming_strings=off;
SET escape_string_warning=off;
SET CONSTRAINTS ALL DEFERRED;

CREATE TABLE "oauth_client_endpoints" (
    "id" bigserial  NOT NULL,
    "client_id" char(40) NOT NULL,
    "redirect_uri" varchar(510) NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "oauth_clients" (
    "id" char(40) NOT NULL,
    "secret" char(40) NOT NULL,
    "name" varchar(510) NOT NULL,
    "auto_approve" int4 NOT NULL DEFAULT '0',
    PRIMARY KEY ("id"),
    UNIQUE ("secret","id")
);

CREATE TABLE "oauth_scopes" (
    "id" bigserial  NOT NULL,
    "scope" varchar(510) NOT NULL,
    "name" varchar(510) NOT NULL,
    "description" varchar(510) DEFAULT NULL,
    PRIMARY KEY ("id"),
    UNIQUE ("scope")
);

CREATE TABLE "oauth_session_access_tokens" (
    "id" bigserial  NOT NULL,
    "session_id" integer  NOT NULL,
    "access_token" char(40) NOT NULL,
    "access_token_expires" integer  NOT NULL,
    PRIMARY KEY ("id"),
    UNIQUE ("access_token","session_id")
);

CREATE TABLE "oauth_session_authcode_scopes" (
    "oauth_session_authcode_id" integer  NOT NULL,
    "scope_id" int2  NOT NULL
);

CREATE TABLE "oauth_session_authcodes" (
    "id" bigserial  NOT NULL,
    "session_id" integer  NOT NULL,
    "auth_code" char(40) NOT NULL,
    "auth_code_expires" integer  NOT NULL,
    PRIMARY KEY ("id")
);

CREATE TABLE "oauth_session_redirects" (
    "session_id" integer  NOT NULL,
    "redirect_uri" varchar(510) NOT NULL,
    PRIMARY KEY ("session_id")
);

CREATE TABLE "oauth_session_refresh_tokens" (
    "session_access_token_id" integer  NOT NULL,
    "refresh_token" char(40) NOT NULL,
    "refresh_token_expires" integer  NOT NULL,
    "client_id" char(40) NOT NULL,
    PRIMARY KEY ("session_access_token_id")
);

CREATE TABLE "oauth_session_token_scopes" (
    "id" bigserial  NOT NULL,
    "session_access_token_id" integer  DEFAULT NULL,
    "scope_id" int2  NOT NULL,
    PRIMARY KEY ("id"),
    UNIQUE ("session_access_token_id","scope_id")
);

DROP TYPE IF EXISTS oauth_sessions_owner_type;
CREATE TYPE oauth_sessions_owner_type AS ENUM ('user','client'); 
CREATE TABLE "oauth_sessions" (
    "id" bigserial  NOT NULL,
    "client_id" char(40) NOT NULL,
    "owner_type" oauth_sessions_owner_type NOT NULL DEFAULT 'user',
    "owner_id" varchar(510) NOT NULL,
    PRIMARY KEY ("id")
);


-- Post-data save --
COMMIT;
START TRANSACTION;

-- Typecasts --
ALTER TABLE "oauth_clients" ALTER COLUMN "auto_approve" DROP DEFAULT, ALTER COLUMN "auto_approve" TYPE boolean USING CAST("auto_approve" as boolean);

-- Foreign keys --
ALTER TABLE "oauth_client_endpoints" ADD CONSTRAINT "f_oaclen_clid" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("id") ON DELETE CASCADE ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX ON "oauth_client_endpoints" ("client_id");
ALTER TABLE "oauth_session_access_tokens" ADD CONSTRAINT "f_oaseto_seid" FOREIGN KEY ("session_id") REFERENCES "oauth_sessions" ("id") ON DELETE CASCADE ON UPDATE NO ACTION DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX ON "oauth_session_access_tokens" ("session_id");
ALTER TABLE "oauth_session_authcode_scopes" ADD CONSTRAINT "oauth_session_authcode_scopes_ibfk_2" FOREIGN KEY ("scope_id") REFERENCES "oauth_scopes" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX ON "oauth_session_authcode_scopes" ("scope_id");
ALTER TABLE "oauth_session_authcode_scopes" ADD CONSTRAINT "oauth_session_authcode_scopes_ibfk_1" FOREIGN KEY ("oauth_session_authcode_id") REFERENCES "oauth_session_authcodes" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX ON "oauth_session_authcode_scopes" ("oauth_session_authcode_id");
ALTER TABLE "oauth_session_authcodes" ADD CONSTRAINT "oauth_session_authcodes_ibfk_1" FOREIGN KEY ("session_id") REFERENCES "oauth_sessions" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX ON "oauth_session_authcodes" ("session_id");
ALTER TABLE "oauth_session_redirects" ADD CONSTRAINT "f_oasere_seid" FOREIGN KEY ("session_id") REFERENCES "oauth_sessions" ("id") ON DELETE CASCADE ON UPDATE NO ACTION DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX ON "oauth_session_redirects" ("session_id");
ALTER TABLE "oauth_session_refresh_tokens" ADD CONSTRAINT "oauth_session_refresh_tokens_ibfk_1" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("id") ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX ON "oauth_session_refresh_tokens" ("client_id");
ALTER TABLE "oauth_session_refresh_tokens" ADD CONSTRAINT "f_oasetore_setoid" FOREIGN KEY ("session_access_token_id") REFERENCES "oauth_session_access_tokens" ("id") ON DELETE CASCADE ON UPDATE NO ACTION DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX ON "oauth_session_refresh_tokens" ("session_access_token_id");
ALTER TABLE "oauth_session_token_scopes" ADD CONSTRAINT "f_oasetosc_scid" FOREIGN KEY ("scope_id") REFERENCES "oauth_scopes" ("id") ON DELETE CASCADE ON UPDATE NO ACTION DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX ON "oauth_session_token_scopes" ("scope_id");
ALTER TABLE "oauth_session_token_scopes" ADD CONSTRAINT "f_oasetosc_setoid" FOREIGN KEY ("session_access_token_id") REFERENCES "oauth_session_access_tokens" ("id") ON DELETE CASCADE ON UPDATE NO ACTION DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX ON "oauth_session_token_scopes" ("session_access_token_id");
ALTER TABLE "oauth_sessions" ADD CONSTRAINT "f_oase_clid" FOREIGN KEY ("client_id") REFERENCES "oauth_clients" ("id") ON DELETE CASCADE ON UPDATE CASCADE DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX ON "oauth_sessions" ("client_id");


COMMIT;