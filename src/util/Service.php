<?php
/*
 * This file is part of the NB Framework package.
 *
 * Copyright (c) 2018 https://nb.cx All rights reserved.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace nbcx\oauth\server\util;

/**
 * Service
 *
 * @link https://nb.cx
 * @author: collin <collin@nb.cx>
 * @date: 2019/4/19
 */
class Service extends \nb\Service {

    protected function error($code, $msg) {
        $this->code = $code;
        $this->msg = $msg;
    }

}