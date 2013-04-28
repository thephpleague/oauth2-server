CREATE TABLE `oauth_clients` (
  `id` CHAR(40) NOT NULL,
  `secret` CHAR(40) NOT NULL,
  `name` VARCHAR(255) NOT NULL,
  `auto_approve` TINYINT(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `u_oacl_clse_clid` (`secret`,`id`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_client_endpoints` (
  `endpoint_id` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `client_id` CHAR(40) NOT NULL,
  `redirect_uri` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`endpoint_id`),
  KEY `i_oaclen_clid` (`client_id`),
  CONSTRAINT `f_oaclen_clid` FOREIGN KEY (`client_id`) REFERENCES `oauth_clients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=INNODB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_sessions` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `client_id` char(40) NOT NULL,
  `owner_type` enum('user','client') NOT NULL DEFAULT 'user',
  `owner_id` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `i_uase_clid_owty_owid` (`client_id`,`owner_type`,`owner_id`),
  CONSTRAINT `f_oase_clid` FOREIGN KEY (`client_id`) REFERENCES `oauth_clients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_session_access_tokens` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `session_id` int(10) unsigned NOT NULL,
  `access_token` char(40) NOT NULL DEFAULT '',
  `access_token_expires` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `u_oaseacto_acto_seid` (`access_token`,`session_id`),
  KEY `f_oaseto_seid` (`session_id`),
  CONSTRAINT `f_oaseto_seid` FOREIGN KEY (`session_id`) REFERENCES `oauth_sessions` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_session_authcodes` (
  `session_id` int(10) unsigned NOT NULL,
  `auth_code` char(40) NOT NULL DEFAULT '',
  `auth_code_expires` int(10) unsigned NOT NULL,
  PRIMARY KEY (`session_id`),
  CONSTRAINT `f_oaseau_seid` FOREIGN KEY (`session_id`) REFERENCES `oauth_sessions` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_session_redirects` (
  `session_id` int(10) unsigned NOT NULL,
  `redirect_uri` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`session_id`),
  CONSTRAINT `f_oasere_seid` FOREIGN KEY (`session_id`) REFERENCES `oauth_sessions` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_session_refresh_tokens` (
  `session_access_token_id` int(10) unsigned NOT NULL,
  `refresh_token` char(40) NOT NULL DEFAULT '',
  PRIMARY KEY (`session_access_token_id`),
  CONSTRAINT `f_oasetore_setoid` FOREIGN KEY (`session_access_token_id`) REFERENCES `oauth_session_access_tokens` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_scopes` (
  `id` SMALLINT(5) UNSIGNED NOT NULL AUTO_INCREMENT,
  `key` VARCHAR(255) NOT NULL,
  `name` VARCHAR(255) NOT NULL,
  `description` VARCHAR(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `u_oasc_sc` (`key`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_session_token_scopes` (
  `session_token_scope_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `session_access_token_id` int(10) unsigned DEFAULT NULL,
  `scope_id` smallint(5) unsigned NOT NULL,
  PRIMARY KEY (`session_token_scope_id`),
  UNIQUE KEY `u_setosc_setoid_scid` (`session_access_token_id`,`scope_id`),
  KEY `f_oasetosc_scid` (`scope_id`),
  CONSTRAINT `f_oasetosc_scid` FOREIGN KEY (`scope_id`) REFERENCES `oauth_scopes` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION,
  CONSTRAINT `f_oasetosc_setoid` FOREIGN KEY (`session_access_token_id`) REFERENCES `oauth_session_access_tokens` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB DEFAULT CHARSET=utf8;