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

use nbcx\oauth\server\model\Client;
use nbcx\oauth\server\model\Scopes;
use nbcx\oauth\server\util\Service;

/**
 * Authorization
 *
 * @link https://nb.cx
 * @author: collin <collin@nb.cx>
 * @date: 2019/4/19
 */
class Authorization extends Service {

    private $config = [
        'allow_implicit' => false,
        'enforce_state'  => true,
        'require_exact_redirect_uri' => true,
        'redirect_status_code' => 302,
    ];

    public function index() {
        // We repeat this, because we need to re-validate. The request could be POSTed
        // by a 3rd-party (because we are not internally enforcing NONCEs, etc)
        if (!$data = $this->validateRequest()) {
            return false;
        }

        if(empty($data['redirect_uri'])) {
            $this->msg = 'redirect_uri can`t empty';
            return false;
        }
        $user_id = 0;
        $authResult = $this->getAuthorizeResponse($data,$user_id);

        list($redirect_uri, $uri_params) = $authResult;

        if (empty($redirect_uri) && !empty($registered_redirect_uri)) {
            $redirect_uri = $registered_redirect_uri;
        }
        e($authResult);
        $uri = $this->buildUri($redirect_uri, $uri_params);
        ed($uri);
    }

    public function api() {
        if (!$data = $this->validateRequest()) {
            return false;
        }

        if(empty($data['redirect_uri'])) {
            $this->msg = 'redirect_uri can`t empty';
            return false;
        }
        $user_id = 0;
        $authResult = $this->getAuthorizeResponse($data,$user_id);

        list($redirect_uri, $uri_params) = $authResult;

        if (empty($redirect_uri) && !empty($registered_redirect_uri)) {
            $redirect_uri = $registered_redirect_uri;
        }
        $this->data = [
            'authorization_code'=> $uri_params['query']['code'],
            'state'=> $uri_params['query']['state'],
        ];
        return true;
    }

    /**
     * Build the absolute URI based on supplied URI and parameters.
     *
     * @param $uri    An absolute URI.
     * @param $params Parameters to be append as GET.
     *
     * @return
     * An absolute URI with supplied parameters.
     *
     * @ingroup oauth2_section_4
     */
    private function buildUri($uri, $params) {
        $parse_url = parse_url($uri);

        // Add our params to the parsed uri
        foreach ($params as $k => $v) {
            if (isset($parse_url[$k])) {
                $parse_url[$k] .= "&" . http_build_query($v, '', '&');
            } else {
                $parse_url[$k] = http_build_query($v, '', '&');
            }
        }

        // Put humpty dumpty back together
        return
            ((isset($parse_url["scheme"])) ? $parse_url["scheme"] . "://" : "")
            . ((isset($parse_url["user"])) ? $parse_url["user"]
                . ((isset($parse_url["pass"])) ? ":" . $parse_url["pass"] : "") . "@" : "")
            . ((isset($parse_url["host"])) ? $parse_url["host"] : "")
            . ((isset($parse_url["port"])) ? ":" . $parse_url["port"] : "")
            . ((isset($parse_url["path"])) ? $parse_url["path"] : "")
            . ((isset($parse_url["query"]) && !empty($parse_url['query'])) ? "?" . $parse_url["query"] : "")
            . ((isset($parse_url["fragment"])) ? "#" . $parse_url["fragment"] : "")
            ;
    }

    public function getAuthorizeResponse($params, $user_id = null) {
        // build the URL to redirect to
        $result = ['query' => []];

        $params += ['scope' => null, 'state' => null];

        $result['query']['code'] = $this->createAuthorizationCode($params['client_id'], $user_id, $params['redirect_uri'], $params['scope']);

        if (isset($params['state'])) {
            $result['query']['state'] = $params['state'];
        }

        return [$params['redirect_uri'], $result];
    }

    public function createAuthorizationCode($client_id, $user_id, $redirect_uri, $scope = null) {
        $code = $this->generateAuthorizationCode();

        \nbcx\oauth\server\model\Authorization::insert([
            'authorization_code'=>$code,
            'client_id'=>$client_id,
            'user_id'=>$user_id,
            'redirect_uri'=>$redirect_uri,
            'scope'=>$scope
        ]);

        return $code;
    }

    /**
     * Generates an unique auth code.
     *
     * Implementing classes may want to override this function to implement
     * other auth code generation schemes.
     *
     * @return
     * An unique auth code.
     *
     * @ingroup oauth2_section_4
     */
    protected function generateAuthorizationCode() {

        $tokenLen = 40;

        if (function_exists('openssl_random_pseudo_bytes')) {
            $randomData = openssl_random_pseudo_bytes(100);
        }
        elseif (@file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 100) . uniqid(mt_rand(), true);
        }
        else {
            $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);
        }

        return substr(hash('sha512', $randomData), 0, $tokenLen);
    }

    private function validateRequest() {

        if(!$client_id = $this->input('client_id')) {
            return $this->error(400,'No client id supplied');
        }

        $client = Client::findId($client_id);
        if($client->empty) {
            return $this->error(400,'The client id supplied is invalid');
        }


        if($client['redirect_uri'] && $client['redirect_uri'] != $this->input('redirect_uri')) {
            return $this->error(400, 'No redirect URI was supplied or stored');
        }

        // Select the redirect URI
        $response_type = $this->input('response_type');

        // for multiple-valued response types - make them alphabetical
        if (false !== strpos($response_type, ' ')) {
            $types = explode(' ', $response_type);
            sort($types);
            $response_type = ltrim(implode(' ', $types));
        }

        $state = $this->input('state');

        switch ($response_type) {
            case self::RESPONSE_TYPE_AUTHORIZATION_CODE:
                if (!$client->checkRestrictedGrantType('authorization_code')) {
                    $this->error(400,'The grant type is unauthorized for this client_id');
                    return false;
                }
                break;
            case self::RESPONSE_TYPE_ACCESS_TOKEN:
                if (!$this->config['allow_implicit']) {
                    $this->error( 400,'implicit grant type not supported');

                    return false;
                }
                if (!$client->checkRestrictedGrantType('implicit')) {
                    $this->error(400, 'The grant type is unauthorized for this client_id');
                    return false;
                }
                break;
            default:
                $this->error(400,'Invalid or missing response type');
                break;
        }

        // validate requested scope if it exists
        $requestedScope = $this->input('scope');


        if ($requestedScope) {
            // restrict scope by client specific scope if applicable,
            // otherwise verify the scope exists
            //$clientScope = $this->clientStorage->getClientScope($client_id);

            $clientScope = $client->scope;

            if ((is_null($clientScope) && !Scopes::exists($requestedScope)) || ($clientScope && !Scopes::check($requestedScope, $clientScope))) {
                $this->error(400,'An unsupported scope was requested');
                return false;
            }
        }
        else {
            // use a globally-defined default scope
            $defaultScope = Scopes::defaultScope($client_id);// $this->scopeUtil->getDefaultScope($client_id);

            if (false === $defaultScope) {
                return $this->error(400,'This application requires you specify a scope parameter');
            }

            $requestedScope = $defaultScope;
        }

        // Validate state parameter exists (if configured to enforce this)
        if ($this->config['enforce_state'] && !$state) {
            return $this->error(400,'The state parameter is required');
        }

        return [
            'scope' => $requestedScope,
            'state' => $state,
            'client_id' => $client_id,
            'redirect_uri' => $client['redirect_uri'],
            'response_type'=> $response_type
        ];
    }

    const RESPONSE_TYPE_AUTHORIZATION_CODE = 'code';
    const RESPONSE_TYPE_ACCESS_TOKEN = 'token';

    protected function getValidResponseTypes() {
        return [
            self::RESPONSE_TYPE_ACCESS_TOKEN,
            self::RESPONSE_TYPE_AUTHORIZATION_CODE,
        ];
    }



}