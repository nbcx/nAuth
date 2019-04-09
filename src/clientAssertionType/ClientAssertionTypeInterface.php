<?php
namespace nbcx\oauth\server\clientAssertionType;

use nbcx\oauth\server\RequestInterface;
use nbcx\oauth\server\ResponseInterface;

/**
 * Interface for all OAuth2 Client Assertion Types
 */
interface ClientAssertionTypeInterface {

    public function validateRequest(RequestInterface $request, ResponseInterface $response);
    public function getClientId();
}
