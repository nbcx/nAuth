<?php
namespace nbcx\oauth\server\TokenType;

use nbcx\oauth\server\RequestInterface;
use nbcx\oauth\server\ResponseInterface;

interface TokenTypeInterface {
    /**
     * Token type identification string
     *
     * ex: "bearer" or "mac"
     */
    public function getTokenType();

    /**
     * Retrieves the token string from the request object
     */
    public function getAccessTokenParameter(RequestInterface $request, ResponseInterface $response);
}
