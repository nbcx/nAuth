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

use nbcx\oauth\server\model\RefreshToken;
use nbcx\oauth\server\util\Service;

/**
 * Token
 *
 * @package service
 * @link https://nb.cx
 * @author: collin <collin@nb.cx>
 * @date: 2019/4/23
 */
class Token extends Service {

    protected $config = [
        'token_type'             => 'bearer',
        'access_lifetime'        => 3600,
        'refresh_token_lifetime' => 1209600,
    ];

    public function index() {
        $grantTypeIdentifier = $this->input('post',['grant_type']);
        if(!$grantTypeIdentifier) {
            return $this->error(400,'The grant type was not specified in the request');
        }

        list($client_id,$client_secret) = $this->input('client_id','client_secret');
        $user_id = 0;
        if($this->validateCode() === false) {
            return false;
        }



        $token = $this->createAccessToken($client_id,$user_id);

        ed($token);

    }

    protected function validateCode() {
        return true;
    }

    public function createAccessToken($client_id, $user_id, $scope = null, $includeRefreshToken = true) {
        $token = [
            "access_token" => $this->generateAccessToken(),
            "expires_in" => $this->config['access_lifetime'],
            "token_type" => $this->config['token_type'],
            "scope" => $scope
        ];
        $expires = date('Y-m-d H:i:s', $this->config['access_lifetime'] ? time() + $this->config['access_lifetime'] : null);
        \nbcx\oauth\server\model\Token::insert([
            'client_id'=>$client_id,
            'access_token'=>$token["access_token"],
            'user_id'=>$user_id,
            'expires'=>$expires,
            'scope'=>$scope
        ]);

        /*
         * Issue a refresh token also, if we support them
         *
         * Refresh Tokens are considered supported if an instance of OAuth2\Storage\RefreshTokenInterface
         * is supplied in the constructor
         */
        if ($includeRefreshToken) {
            $token["refresh_token"] = $this->generateRefreshToken();
            $expires = 0;
            if ($this->config['refresh_token_lifetime'] > 0) {
                $expires = time() + $this->config['refresh_token_lifetime'];
            }

            RefreshToken::insert([
                'refresh_token'=>$token["refresh_token"],
                'client_id'=>$client_id,
                'user_id'=>$user_id,
                'expires'=>date('Y-m-d H:i:s',$expires),
                'scope'=>$scope
            ]);
        }

        return $token;
    }

    /**
     * Generates an unique refresh token
     *
     * Implementing classes may want to override this function to implement
     * other refresh token generation schemes.
     *
     * @return
     * An unique refresh.
     *
     * @ingroup oauth2_section_4
     * @see OAuth2::generateAccessToken()
     */
    protected function generateRefreshToken() {
        return $this->generateAccessToken(); // let's reuse the same scheme for token generation
    }

    protected function generateAccessToken() {

        if (function_exists('openssl_random_pseudo_bytes')) {
            $randomData = openssl_random_pseudo_bytes(20);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }
        if (@file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 20);
            if ($randomData !== false && strlen($randomData) === 20) {
                return bin2hex($randomData);
            }
        }
        // Last resort which you probably should just get rid of:
        $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);

        return substr(hash('sha512', $randomData), 0, 40);
    }
}