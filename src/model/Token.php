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
 * Token
 *
 * @package nbcx\oauth\server\model
 * @link https://nb.cx
 * @author: collin <collin@nb.cx>
 * @date: 2019/4/19
 */
class Token extends Model {

    protected static function __config() {
        return ['access_tokens', 'access_token'];
    }


}