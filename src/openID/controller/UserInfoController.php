<?php
namespace nbcx\oauth\server\openID\Controller;

use nbcx\oauth\server\Scope;
use nbcx\oauth\server\tokenType\TokenTypeInterface;
use nbcx\oauth\server\storage\AccessTokenInterface;
use nbcx\oauth\server\openID\Storage\UserClaimsInterface;
use nbcx\oauth\server\controller\ResourceController;
use nbcx\oauth\server\scopeInterface;
use nb\request\Driver as RequestInterface;
use nb\response\Driver as ResponseInterface;

/**
 * @see \nbcx\oauth\server\controller\UserInfoControllerInterface
 */
class UserInfoController extends ResourceController implements UserInfoControllerInterface {
    private $token;

    protected $tokenType;
    protected $tokenStorage;
    protected $userClaimsStorage;
    protected $config;
    protected $scopeUtil;

    public function __construct(TokenTypeInterface $tokenType, AccessTokenInterface $tokenStorage, UserClaimsInterface $userClaimsStorage, $config = [], ScopeInterface $scopeUtil = null) {
        $this->tokenType = $tokenType;
        $this->tokenStorage = $tokenStorage;
        $this->userClaimsStorage = $userClaimsStorage;

        $this->config = array_merge([
            'www_realm' => 'Service',
        ], $config);

        if (is_null($scopeUtil)) {
            $scopeUtil = new Scope();
        }
        $this->scopeUtil = $scopeUtil;
    }

    public function handleUserInfoRequest(RequestInterface $request, ResponseInterface $response) {
        if (!$this->verifyResourceRequest($request, $response, 'openid')) {
            return;
        }

        $token = $this->getToken();
        $claims = $this->userClaimsStorage->getUserClaims($token['user_id'], $token['scope']);
        // The sub Claim MUST always be returned in the UserInfo Response.
        // http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
        $claims += [
            'sub' => $token['user_id'],
        ];
        $response->addParameters($claims);
    }
}
