CREATE TABLE `oauth_clients` (
  `client_id` CHAR(40) NOT NULL,
  `client_secret` CHAR(40) NOT NULL,
  `client_name` VARCHAR(255) NOT NULL,
  `auto_approve` TINYINT(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`client_id`),
  UNIQUE KEY `u_oacl_clse_clid` (`client_secret`,`client_id`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_client_endpoints` (
  `endpoint_id` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `client_id` CHAR(40) NOT NULL,
  `redirect_uri` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`endpoint_id`),
  KEY `i_oaclen_clid` (`client_id`),
  CONSTRAINT `f_oaclen_clid` FOREIGN KEY (`client_id`) REFERENCES `oauth_clients` (`client_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=INNODB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_session` (
  `session_id` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `client_id` CHAR(40) NOT NULL,
  `owner_type` ENUM('user','client') NOT NULL DEFAULT 'user',
  `owner_id` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`session_id`),
  KEY `i_uase_clid_owty_owid` (`client_id`,`owner_type`,`owner_id`),
  CONSTRAINT `f_oase_clid` FOREIGN KEY (`client_id`) REFERENCES `oauth_clients` (`client_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=INNODB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_session_access_token` (
  `session_token_id` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `session_id` INT(10) UNSIGNED NOT NULL,
  `access_token` CHAR(40) CHARACTER SET utf8 NOT NULL DEFAULT '',
  `access_token_expires` INT(10) UNSIGNED NOT NULL,
  PRIMARY KEY (`session_token_id`),
  UNIQUE KEY `u_oaseacto_acto_seid` (`access_token`,`session_id`),
  KEY `f_oaseto_seid` (`session_id`),
  CONSTRAINT `f_oaseto_seid` FOREIGN KEY (`session_id`) REFERENCES `oauth_session` (`session_id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=INNODB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_session_authcode` (
  `session_id` int(10) unsigned NOT NULL,
  `auth_code` char(40) CHARACTER SET utf8 NOT NULL DEFAULT '',
  `auth_code_expires` int(10) unsigned NOT NULL,
  PRIMARY KEY (`session_id`),
  CONSTRAINT `f_oaseau_seid` FOREIGN KEY (`session_id`) REFERENCES `oauth_session` (`session_id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_session_redirect` (
  `session_id` INT(10) UNSIGNED NOT NULL,
  `redirect_uri` VARCHAR(255) CHARACTER SET utf8 NOT NULL DEFAULT '',
  PRIMARY KEY (`session_id`),
  CONSTRAINT `f_oasere_seid` FOREIGN KEY (`session_id`) REFERENCES `oauth_session` (`session_id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=INNODB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_session_refresh_token` (
  `session_token_id` INT(10) UNSIGNED NOT NULL,
  `refresh_token` CHAR(40) CHARACTER SET utf8 NOT NULL DEFAULT '',
  PRIMARY KEY (`session_token_id`),
  CONSTRAINT `f_oasetore_setoid` FOREIGN KEY (`session_token_id`) REFERENCES `oauth_session_access_token` (`session_token_id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=INNODB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_scopes` (
  `scope_id` SMALLINT(5) UNSIGNED NOT NULL AUTO_INCREMENT,
  `scope_key` VARCHAR(255) NOT NULL,
  `scope_name` VARCHAR(255) NOT NULL,
  `scope_description` VARCHAR(255) DEFAULT NULL,
  PRIMARY KEY (`scope_id`),
  UNIQUE KEY `u_oasc_sc` (`scope_key`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_session_token_scope` (
  `session_token_scope_id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  `session_token_id` INT(10) UNSIGNED NOT NULL,
  `scope_id` SMALLINT(5) UNSIGNED NOT NULL,
  PRIMARY KEY (`session_token_scope_id`),
  UNIQUE KEY `u_setosc_setoid_scid` (`session_token_id`,`scope_id`),
  KEY `f_oasetosc_scid` (`scope_id`),
  CONSTRAINT `f_oasetosc_setoid` FOREIGN KEY (`session_token_id`) REFERENCES `oauth_session_access_token` (`session_token_id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `f_oasetosc_scid` FOREIGN KEY (`scope_id`) REFERENCES `oauth_scopes` (`scope_id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=INNODB DEFAULT CHARSET=utf8;