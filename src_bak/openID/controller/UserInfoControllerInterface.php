<?php
namespace nbcx\oauth\server\OpenID\Controller;

use nb\request\Driver as RequestInterface;
use nb\response\Driver as ResponseInterface;

/**
 *  This controller is called when the user claims for OpenID Connect's
 *  UserInfo endpoint should be returned.
 *
 *  ex:
 *  > $response = new OAuth2\Response();
 *  > $userInfoController->handleUserInfoRequest(
 *  >     OAuth2\Request::createFromGlobals(),
 *  >     $response;
 *  > $response->send();
 *
 */
interface UserInfoControllerInterface {

    public function handleUserInfoRequest(RequestInterface $request, ResponseInterface $response);
}
