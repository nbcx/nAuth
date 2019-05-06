<?php
/*
 * This file is part of the NB Framework package.
 *
 * Copyright (c) 2018 https://nb.cx All rights reserved.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace service;

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


    public function verifyResourceRequest(RequestInterface $request, ResponseInterface $response, $scope = null) {
        $token = $this->getAccessTokenData($request, $response);

        // Check if we have token data
        if (is_null($token)) {
            return false;
        }

        /**
         * Check scope, if provided
         * If token doesn't have a scope, it's null/empty, or it's insufficient, then throw 403
         * @see http://tools.ietf.org/html/rfc6750#section-3.1
         */
        if ($scope && (!isset($token["scope"]) || !$token["scope"] || !$this->scopeUtil->checkScope($scope, $token["scope"]))) {
            $response->setError(403, 'insufficient_scope', 'The request requires higher privileges than provided by the access token');
            $response->addHttpHeaders([
                'WWW-Authenticate' => sprintf('%s realm="%s", scope="%s", error="%s", error_description="%s"',
                    $this->tokenType->getTokenType(),
                    $this->config['www_realm'],
                    $scope,
                    $response->getParameter('error'),
                    $response->getParameter('error_description')
                )
            ]);

            return false;
        }

        // allow retrieval of the token
        $this->token = $token;

        return (bool) $token;
    }


    public function getAccessTokenData(RequestInterface $request, ResponseInterface $response) {
        // Get the token parameter

        if ($token_param = $this->getAccessTokenParameter($request, $response)) {
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

        $authHeader = sprintf('%s realm="%s"', $this->tokenType->getTokenType(), $this->config['www_realm']);

        if ($error = $response->getParameter('error')) {
            $authHeader = sprintf('%s, error="%s"', $authHeader, $error);
            if ($error_description = $response->getParameter('error_description')) {
                $authHeader = sprintf('%s, error_description="%s"', $authHeader, $error_description);
            }
        }

        $response->addHttpHeaders(['WWW-Authenticate' => $authHeader]);

        return null;
    }

    public function getAccessTokenParameter(RequestInterface $request, ResponseInterface $response) {
        $headers = $request->headers('AUTHORIZATION');

        /**
         * Ensure more than one method is not used for including an
         * access token
         *
         * @see http://tools.ietf.org/html/rfc6750#section-3.1
         */
        $methodsUsed = !empty($headers) + (bool) ($request->query($this->config['token_param_name'])) + (bool) ($request->request($this->config['token_param_name']));
        if ($methodsUsed > 1) {
            $this->error(400, 'Only one method may be used to authenticate at a time (Auth header, GET or POST)');
            return null;
        }

        /**
         * If no authentication is provided, set the status code
         * to 401 and return no other error information
         *
         * @see http://tools.ietf.org/html/rfc6750#section-3.1
         */
        if ($methodsUsed == 0) {
            $response->setStatusCode(401);

            return null;
        }

        // HEADER: Get the access token from the header
        if (!empty($headers)) {
            if (!preg_match('/' . $this->config['token_bearer_header_name'] . '\s(\S+)/i', $headers, $matches)) {
                $response->setError(400, 'invalid_request', 'Malformed auth header');

                return null;
            }

            return $matches[1];
        }

        if ($request->request($this->config['token_param_name'])) {
            // // POST: Get the token from POST data
            if (!in_array(strtolower($request->server('REQUEST_METHOD')), array('post', 'put'))) {
                $response->setError(400, 'invalid_request', 'When putting the token in the body, the method must be POST or PUT', '#section-2.2');

                return null;
            }

            $contentType = $request->server('CONTENT_TYPE');
            if (false !== $pos = strpos($contentType, ';')) {
                $contentType = substr($contentType, 0, $pos);
            }

            if ($contentType !== null && $contentType != 'application/x-www-form-urlencoded') {
                // IETF specifies content-type. NB: Not all webservers populate this _SERVER variable
                // @see http://tools.ietf.org/html/rfc6750#section-2.2
                $response->error(400, 'invalid_request', 'The content type for POST requests must be "application/x-www-form-urlencoded"');

                return null;
            }

            return $request->request($this->config['token_param_name']);
        }

        // GET method
        return $request->query($this->config['token_param_name']);
    }

}