<?php
/*
 * This file is part of the NB Framework package.
 *
 * Copyright (c) 2018 https://nb.cx All rights reserved.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace nbcx\oauth\server\service;

use nbcx\oauth\server\model\Token;
use nbcx\oauth\server\util\Service;

/**
 * Resource
 *
 * @package service
 * @link https://nb.cx
 * @author: collin <collin@nb.cx>
 * @date: 2019/5/6
 */
class Resource extends Service {

    protected $config = [
        'www_realm' => 'Service',
        'token_param_name'         => 'access_token',
        'token_bearer_header_name' => 'Bearer',
    ];

    protected $token;

    public function __construct($controller) {
        parent::__construct($controller);

        $this->token = $this->getAccessTokenData();
    }

    protected function verify($scope = null) {
        $token = $this->token;

        // Check if we have token data
        if (is_null($this->token)) {
            return false;
        }

        /**
         * Check scope, if provided
         * If token doesn't have a scope, it's null/empty, or it's insufficient, then throw 403
         * @see http://tools.ietf.org/html/rfc6750#section-3.1
         */
        if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$this->checkScope($scope, $token["scope"]))) {
            $this->error(403, 'The request requires higher privileges than provided by the access token');
            return false;
        }

        // allow retrieval of the token
        $this->token = $token;

        return (bool) $token;
    }


    /**
     * Check if everything in required scope is contained in available scope.
     *
     * @param $required_scope
     * A space-separated string of scopes.
     *
     * @return
     * TRUE if everything in required scope is contained in available scope,
     * and FALSE if it isn't.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-7
     *
     * @ingroup oauth2_section_7
     */
    private function checkScope($required_scope, $available_scope) {
        $required_scope = explode(' ', trim($required_scope));
        $available_scope = explode(' ', trim($available_scope));

        return (count(array_diff($required_scope, $available_scope)) == 0);
    }


    private function getAccessTokenData() {
        // Get the token parameter
        if ($token_param = $this->input($this->config['token_param_name'])) {
            // Get the stored token data (from the implementing subclass)
            // Check we have a well formed token
            // Check token expiration (expires is a mandatory paramter)
            if (!$token =  Token::findId($token_param)) { //$this->tokenStorage->getAccessToken($token_param)
                $this->error(401, 'The access token provided is invalid');
            }
            elseif (!isset($token["expires"]) || !isset($token["client_id"])) {
                $this->error(401, 'Malformed token (missing "expires")');
            }
            elseif (time() > $token["expires"]) {
                $this->error(401, 'The access token provided has expired');
            }
            else {
                return $token;
            }
        }
        $this->error(401, 'The parameter access token missing');
        return null;
    }



}