<?php

namespace MediaWiki\Extension\LDAPAuthentication\Auth;

use MediaWiki\Auth\AuthenticationResponse as MWAuthenticationResponse;

class AuthenticationResponse extends MWAuthenticationResponse {

	public $domain = '';

	public static function newPass( $username = null, $domain = null ) {
		$res = parent::newPass( $username );
		$res->domain = $domain;
		return $domain;
	}
}