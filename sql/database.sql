CREATE TABLE `oauth_client_endpoints` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `client_id` varchar(40) NOT NULL DEFAULT '',
  `redirect_uri` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `client_id` (`client_id`),
  CONSTRAINT `oauth_client_endpoints_ibfk_1` FOREIGN KEY (`client_id`) REFERENCES `oauth_clients` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_clients` (
  `id` varchar(40) NOT NULL DEFAULT '',
  `secret` varchar(40) NOT NULL DEFAULT '',
  `name` varchar(255) NOT NULL DEFAULT '',
  `auto_approve` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_session_scopes` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `session_id` int(11) unsigned NOT NULL,
  `scope_id` int(11) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `session_id` (`session_id`),
  KEY `scope_id` (`scope_id`),
  CONSTRAINT `oauth_session_scopes_ibfk_5` FOREIGN KEY (`scope_id`) REFERENCES `oauth_scopes` (`id`) ON DELETE CASCADE,
  CONSTRAINT `oauth_session_scopes_ibfk_4` FOREIGN KEY (`session_id`) REFERENCES `oauth_sessions` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_sessions` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `client_id` varchar(40) NOT NULL DEFAULT '',
  `redirect_uri` varchar(250) DEFAULT '',
  `owner_type` enum('user','client') NOT NULL DEFAULT 'user',
  `owner_id` varchar(255) DEFAULT '',
  `auth_code` varchar(40) DEFAULT '',
  `access_token` varchar(40) DEFAULT '',
  `refresh_token` varchar(40) DEFAULT '',
  `access_token_expires` int(10) DEFAULT NULL,
  `stage` enum('requested','granted') NOT NULL DEFAULT 'requested',
  `first_requested` int(10) unsigned NOT NULL,
  `last_updated` int(10) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `client_id` (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `oauth_scopes` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `scope` varchar(255) NOT NULL DEFAULT '',
  `name` varchar(255) NOT NULL DEFAULT '',
  `description` varchar(255) DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `scope` (`scope`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;