<?php

namespace MediaWiki\Extensions\LDAPAuthentication;

use Exception;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Extensions\LDAPProvider\ClientFactory;
use MediaWiki\Extensions\LDAPProvider\UserDomainStore;
use PluggableAuth as PluggableAuthBase;
use PluggableAuthLogin;
use User;

class PluggableAuth extends PluggableAuthBase {

	const DOMAIN_SESSION_KEY = 'ldap-authentication-selected-domain';

	/**
	 * Authenticates against LDAP
	 * @param int &$id not used
	 * @param string &$username set to username
	 * @param string &$realname set to real name
	 * @param string &$email set to email
	 * @param string &$errorMessage any errors
	 * @return bool false on failure
	 * @SuppressWarnings( UnusedFormalParameter )
	 * @SuppressWarnings( ShortVariable )
	 */
	public function authenticate( &$id, &$username, &$realname, &$email, &$errorMessage ) {
		$authManager = AuthManager::singleton();
		$extraLoginFields = $authManager->getAuthenticationSessionData(
			PluggableAuthLogin::EXTRALOGINFIELDS_SESSION_KEY
		);

		$domain = $extraLoginFields[ExtraLoginFields::DOMAIN];
		$username = $extraLoginFields[ExtraLoginFields::USERNAME];
		$password = $extraLoginFields[ExtraLoginFields::PASSWORD];

		if ( $domain === ExtraLoginFields::DOMAIN_VALUE_LOCAL ) {
			return true;
		}

		$ldapClient = ClientFactory::getInstance()->getForDomain( $domain );
		if ( !$ldapClient->canBindAs( $username, $password ) ) {
			$errorMessage =
				wfMessage(
					'ldapauthentication-error-authentication-failed',
					$domain
				)->text();
			return false;
		}
		try {
			$result = $ldapClient->getUserInfo( $username );
			$username = $result[Config::USERINFO_USERNAME_ATTR];
			$realname = $result[Config::USERINFO_REALNAME_ATTR];
			$email = $result[Config::USERINFO_EMAIL_ATTR];
		} catch ( Exception $ex ) {
			$errorMessage =
				wfMessage(
					'ldapauthentication-error-authentication-failed-userinfo',
					$domain
				)->text();
			return false;
		}

		/* This is a workaround: As "PluggableAuthUserAuthorization" hook is
		 * being called before PluggableAuth::saveExtraAttributes (see below)
		 * we can not rely on LdapProvider\UserDomainStore here. We can also
		 * not persist the domain here, as the user id may be null (fist login)
		 */
		$authManager->setAuthenticationSessionData(
			static::DOMAIN_SESSION_KEY,
			$domain
		);
	}

	/**
	 * @param User &$user to log out
	 */
	public function deauthenticate( User &$user ) {
		// Nothing to do, really
		$user = null;
	}

	/**
	 * @param int $userId for user
	 */
	public function saveExtraAttributes( $userId ) {
		$authManager = AuthManager::singleton();
		$domain = $authManager->getAuthenticationSessionData(
			static::DOMAIN_SESSION_KEY
		);

		$userDomainStore = new UserDomainStore(
			\MediaWiki\MediaWikiServices::getInstance()->getDBLoadBalancer()
		);

		$userDomainStore->setDomainForUser(
			\User::newFromId( $userId ),
			$domain
		);
	}
}
