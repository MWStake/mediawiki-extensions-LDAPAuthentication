<?php

namespace MediaWiki\Extension\LDAPAuthentication\Auth;

use MediaWiki\Auth\AbstractPasswordPrimaryAuthenticationProvider;
use MediaWiki\Auth\LocalPasswordPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Extension\LDAPProvider\ClientFactory;
use MediaWiki\Extension\LDAPProvider\UserDomainStore;

class PrimaryAuthenticationProvider extends LocalPasswordPrimaryAuthenticationProvider {
	/**
	 *
	 * @param string $action
	 * @param array $options
	 * @return AuthenticationRequest[]
	 */
	public function getAuthenticationRequests( $action, array $options ) {
		$req = new DomainAndPasswordAuthenticationRequest();
		return [ $req ];
	}

	/**
	 *
	 * @param AuthenticationRequest[] $reqs
	 * @return AuthenticationResponse
	 */
	public function beginPrimaryAuthentication( array $reqs ) {
		$req = AuthenticationRequest::getRequestByClass(
			$reqs,
			DomainAndPasswordAuthenticationRequest::class
		);
		if ( $req instanceof DomainAndPasswordAuthenticationRequest === false ) {
			return AuthenticationResponse::newAbstain();
		}

		$selectedDomain = $req->domain;
		if( $selectedDomain === 'local' ) {
			return AuthenticationResponse::newAbstain();
		}
		return AuthenticationResponse::newPass(
			$req->username,
			$selectedDomain
		);
		$client = ClientFactory::getInstance()->getForDomain( $selectedDomain );
		$isAuthenticated = $client->canBindAs( $req->username, $req->password );

		if( !$isAuthenticated ) {
			return AuthenticationResponse::newFail(
				wfMessage( 'ldapauthentication-error-authentication-failed' )
			);
		}

		return AuthenticationResponse::newPass(
			$req->username,
			$selectedDomain
		);
	}

	/**
	 *
	 * @param \User $user
	 * @param \User $creator
	 * @param AuthenticationResponse $res
	 * @return null
	 */
	public function finishAccountCreation( $user, $creator, AuthenticationResponse $res ) {
		$parentReturn = parent::finishAccountCreation( $user, $creator, $res );

		$userDomainStore = new UserDomainStore();
		$userDomainStore->setDomainForUser( $user, $res->domain );

		return $parentReturn;
	}
}