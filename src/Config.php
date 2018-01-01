<?php

namespace MediaWiki\Extensions\LDAPAuthentication;

class Config {
	const USERINFO_USERNAME_ATTR = 'usernameattribute';
	const USERINFO_REALNAME_ATTR = 'realnameattribute';
	const USERINFO_EMAIL_ATTR = 'emailattribute';

	const VERSION = "1.0.0-alpha";

	/**
	 * Convenience function to show the tests we can actually load.
	 *
	 * @return string
	 */
	public static function getVersion() {
		return self::VERSION;
	}
}
