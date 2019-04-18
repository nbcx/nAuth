<?php
namespace nbcx\oauth\server\clientAssertionType;

use nb\request\Driver as RequestInterface;
use nb\response\Driver as ResponseInterface;

/**
 * Interface for all OAuth2 Client Assertion Types
 */
interface ClientAssertionTypeInterface {

    public function validateRequest(RequestInterface $request, ResponseInterface $response);
    public function getClientId();
}
