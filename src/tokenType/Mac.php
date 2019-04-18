<?php
namespace nbcx\oauth\server\tokenType;

use nb\request\Driver as RequestInterface;
use nb\response\Driver as ResponseInterface;

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
