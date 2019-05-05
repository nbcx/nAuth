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

use nbcx\oauth\server\util\Service;

/**
 * RefreshToken
 *
 * @package service
 * @link https://nb.cx
 * @author: collin <collin@nb.cx>
 * @date: 2019/4/24
 */
class RefreshToken extends Token {

    private $refreshToken;

    public function index() {
        $this->config = array_merge($this->config,[
            'always_issue_new_refresh_token' => true,
            'unset_refresh_token_after_use' => true
        ]);

        if(!$this->validateRequest()) {
            return false;
        }

        if($token = $this->createAccessToken()) {
            $this->data = $token;
            return true;
        }

        return false;
    }

    private function validateRequest() {

        if (!$refresh_token = $this->input("refresh_token")) {
            $this->error(400, 'Missing parameter: "refresh_token" is required');

            return false;
        }

        $refreshToken = \nbcx\oauth\server\model\RefreshToken::findId($refresh_token);

        if (!$refreshToken) {
            $this->error(400, 'Invalid refresh token');

            return false;
        }

        if ($refreshToken['expires'] > 0 && $refreshToken["expires"] < time()) {
            $this->error(400, 'Refresh token has expired');

            return false;
        }

        // store the refresh token locally so we can delete it when a new refresh token is generated
        $this->refreshToken = $refreshToken;

        return true;
    }


    public function createAccessToken() {

        $client_id = $this->refreshToken['refresh_token'];
        $user_id   = $this->refreshToken['user_id'];
        $scope     = $this->refreshToken['scope'];


        $issueNewRefreshToken = $this->config['always_issue_new_refresh_token'];
        $unsetRefreshToken = $this->config['unset_refresh_token_after_use'];
        $token = parent::createAccessToken($client_id, $user_id, $scope, $issueNewRefreshToken);

        if ($unsetRefreshToken) {
            \nbcx\oauth\server\model\RefreshToken::deleteId($this->refreshToken['refresh_token']);
        }

        return $token;
    }
}