<?php

namespace MediaWiki\Extension\LDAPAuthentication;

use PluggableAuth as PluggableAuthBase;
use PluggableAuthLogin;
use MediaWiki\Extension\LDAPAuthentication\ExtraLoginFields;
use MediaWiki\Extension\LDAPProvider\ClientFactory;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\LDAPProvider\UserDomainStore;

class PluggableAuth extends PluggableAuthBase {

	const DOMAIN_SESSION_KEY = 'ldap-authentication-selected-domain';

	/**
	 *
	 * @var string
	 */
	protected $selectedDomain = '';

	/**
	 * Authenticates against LDAP
	 * @param int $id
	 * @param string $username
	 * @param string $realname
	 * @param string $email
	 * @param string $errorMessage
	 */
	public function authenticate( &$id, &$username, &$realname, &$email, &$errorMessage ) {
		$authManager = AuthManager::singleton();
		$extraLoginFields = $authManager->getAuthenticationSessionData(
			PluggableAuthLogin::EXTRALOGINFIELDS_SESSION_KEY
		);

		$this->selectedDomain = $extraLoginFields[ExtraLoginFields::DOMAIN];
		$username = $extraLoginFields[ExtraLoginFields::USERNAME];
		$password = $extraLoginFields[ExtraLoginFields::PASSWORD];

		if( $this->selectedDomain === ExtraLoginFields::DOMAIN_VALUE_LOCAL ) {
			return true;
		}

		$ldapClient = ClientFactory::getInstance()->getForDomain( $this->selectedDomain );
		if( !$ldapClient->canBindAs( $username, $password ) ) {
			$errorMessage =
				wfMessage(
					'ldapauthentication-error-authentication-failed',
					$this->selectedDomain
				)->text();
			return false;
		}
		try {
			$result = $ldapClient->getUserInfo( $username );
			$username = $result[Config::USERINFO_USERNAME_ATTR];
			$realname = $result[Config::USERINFO_REALNAME_ATTR];
			$email = $result[Config::USERINFO_EMAIL_ATTR];
		} catch( \Exception $ex ) {
			$errorMessage =
				wfMessage(
					'ldapauthentication-error-authentication-failed-userinfo',
					$this->selectedDomain
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
			$this->selectedDomain
		);

		return true;
	}

	/**
	 *
	 * @param \User $user
	 */
	public function deauthenticate( \User &$user ) {
		//Nothing to do
	}

	/**
	 *
	 * @param int $id
	 */
	public function saveExtraAttributes( $id ) {
		$userDomainStore = new UserDomainStore(
			\MediaWiki\MediaWikiServices::getInstance()->getDBLoadBalancer()
		);

		$userDomainStore->setDomainForUser(
			\User::newFromId( $id ),
			$this->selectedDomain
		);
	}
}