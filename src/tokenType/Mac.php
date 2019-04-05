<?php
namespace nAuth\tokenType;

use nAuth\RequestInterface;
use nAuth\ResponseInterface;

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
