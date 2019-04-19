<?php
namespace nbcx\oauth\server\TokenType;

use nb\request\Driver as RequestInterface;
use nb\response\Driver as ResponseInterface;

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
