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

        }
    }

    private function validateRequest() {

        if(!$client_id = $this->input('client_id')) {
            $this->error(400,'No client id supplied');
        }

        $client = Client::findId($client_id);
        if($client->empty) {
            $this->error(400,'The client id supplied is invalid');
        }


        if($client['redirect_uri'] && $client['redirect_uri'] != $this->input('redirect_uri')) {
            $this->error(400, 'No redirect URI was supplied or stored');
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
                $this->error(400,'This application requires you specify a scope parameter');
                return false;
            }

            $requestedScope = $defaultScope;
        }

        // Validate state parameter exists (if configured to enforce this)
        if ($this->config['enforce_state'] && !$state) {
            $this->error(400,'The state parameter is required');
            return false;
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