<?php
namespace nAuth\TokenType;

use nAuth\RequestInterface;
use nAuth\ResponseInterface;

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
