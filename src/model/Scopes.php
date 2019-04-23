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
 * Scopes
 *
 * @package nbcx\oauth\server\model
 * @link https://nb.cx
 * @author: collin <collin@nb.cx>
 * @date: 2019/4/19
 */
class Scopes extends Model {

    public function index() {

    }

    /* ScopeInterface */
    public static function exists($scope) {
        $scope = explode(' ', $scope);
        $whereIn = implode(',', array_fill(0, count($scope), '?'));


        return true;
    }


    public static function check($required_scope, $available_scope) {
        $required_scope = explode(' ', trim($required_scope));
        $available_scope = explode(' ', trim($available_scope));

        return (count(array_diff($required_scope, $available_scope)) == 0);
    }

    public static function defaultScope($client_id = null) {

        $result = self::dao()->fetchs('is_default=1',null,'scope');

        //$stmt = $this->db->prepare(sprintf('SELECT scope FROM %s WHERE is_default=:is_default', $this->config['scope_table']));
        //$stmt->execute(['is_default' => true]);

        if ($result) {
            $defaultScope = array_map(function ($row) {
                return $row['scope'];
            }, $result);

            return implode(' ', $defaultScope);
        }

        return null;
    }

}