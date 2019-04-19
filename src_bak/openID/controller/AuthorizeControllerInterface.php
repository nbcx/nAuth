<?php
namespace nbcx\oauth\server\openID\Controller;

interface AuthorizeControllerInterface {

    const RESPONSE_TYPE_ID_TOKEN = 'id_token';
    const RESPONSE_TYPE_ID_TOKEN_TOKEN = 'id_token token';
    const RESPONSE_TYPE_CODE_ID_TOKEN = 'code id_token';
}
