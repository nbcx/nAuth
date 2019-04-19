<?php
/*
 * This file is part of the NB Framework package.
 *
 * Copyright (c) 2018 https://nb.cx All rights reserved.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace nbcx\oauth\server\model;

use nb\Model;

/**
 * Client
 *
 * @package nbcx\oauth\server\model
 * @link https://nb.cx
 * @author: collin <collin@nb.cx>
 * @date: 2019/4/19
 *
 * @property  string id
 * @property  string secret
 * @property  string redirect_uri
 * @property  string grant_types
 * @property  string scope
 * @property  string user_id
 */
class Client extends Model {

    protected static function __config() {
        return ['clients', 'client_id'];
    }

    protected function ___id() {
        return $this->client_id;
    }

    protected function ___secret() {
        return $this->client_secret;
    }

    public function checkRestrictedGrantType($grant_type) {

        if ($this->grant_types) {
            $grant_types = explode(' ', $this->grant_types);

            return in_array($grant_type, (array) $grant_types);
        }

        // if grant_types are not defined, then none are restricted
        return true;
    }

}