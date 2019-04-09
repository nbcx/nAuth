<?php
namespace nbcx\oauth\server\tokenType;

use nbcx\oauth\server\RequestInterface;
use nbcx\oauth\server\ResponseInterface;

/**
 * This is not yet supported!
 */
class Mac implements TokenTypeInterface {

    public function getTokenType() {
        return 'mac';
    }

    public function getAccessTokenParameter(RequestInterface $request, ResponseInterface $response) {
        throw new \LogicException("Not supported");
    }
}
