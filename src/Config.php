<?php

namespace MediaWiki\Extensions\LDAPAuthentication;

use GlobalVarConfig;

class Config extends GlobalVarConfig {
	const USERINFO_USERNAME_ATTR = 'usernameattribute';
	const USERINFO_REALNAME_ATTR = 'realnameattribute';
	const USERINFO_EMAIL_ATTR = 'emailattribute';

	const VERSION = "1.0.0-alpha";

	public function __construct() {
		parent::__construct( 'LDAPAuthentication' );
	}

	/**
	 * Factory method for MediaWikiServices
	 * @return Config
	 */
	public static function newInstance() {
		return new self();
	}

	/**
	 * Convenience function to show the tests we can actually load.
	 *
	 * @return string
	 */
	public static function getVersion() {
		return self::VERSION;
	}
}
