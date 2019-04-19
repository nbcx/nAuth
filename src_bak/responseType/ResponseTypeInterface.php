<?php
namespace nbcx\oauth\server\ResponseType;

interface ResponseTypeInterface {

    public function getAuthorizeResponse($params, $user_id = null);
}
