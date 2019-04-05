<?php
namespace nAuth\clientAssertionType;

use nAuth\RequestInterface;
use nAuth\ResponseInterface;

/**
 * Interface for all OAuth2 Client Assertion Types
 */
interface ClientAssertionTypeInterface {

    public function validateRequest(RequestInterface $request, ResponseInterface $response);
    public function getClientId();
}
