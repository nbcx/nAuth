<?php
namespace nbcx\oauth\server;

use nbcx\oauth\server\controller\ResourceControllerInterface;
use nbcx\oauth\server\controller\ResourceController;
use nbcx\oauth\server\openID\controller\UserInfoControllerInterface;
use nbcx\oauth\server\openID\controller\UserInfoController;
use nbcx\oauth\server\openID\controller\AuthorizeController as OpenIDAuthorizeController;
use nbcx\oauth\server\openID\responseType\AuthorizationCode as OpenIDAuthorizationCodeResponseType;
use nbcx\oauth\server\openID\storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;
use nbcx\oauth\server\openID\grantType\AuthorizationCode as OpenIDAuthorizationCodeGrantType;
use nbcx\oauth\server\controller\AuthorizeControllerInterface;
use nbcx\oauth\server\controller\AuthorizeController;
use nbcx\oauth\server\controller\TokenControllerInterface;
use nbcx\oauth\server\controller\TokenController;
use nbcx\oauth\server\clientAssertionType\ClientAssertionTypeInterface;
use nbcx\oauth\server\clientAssertionType\HttpBasic;
use nbcx\oauth\server\responseType\ResponseTypeInterface;
use nbcx\oauth\server\responseType\AuthorizationCode as AuthorizationCodeResponseType;
use nbcx\oauth\server\responseType\AccessToken;
use nbcx\oauth\server\responseType\JwtAccessToken;
use nbcx\oauth\server\openID\ResponseType\CodeIdToken;
use nbcx\oauth\server\openID\ResponseType\IdToken;
use nbcx\oauth\server\openID\ResponseType\IdTokenToken;
use nbcx\oauth\server\tokenType\TokenTypeInterface;
use nbcx\oauth\server\tokenType\Bearer;
use nbcx\oauth\server\grantType\GrantTypeInterface;
use nbcx\oauth\server\grantType\UserCredentials;
use nbcx\oauth\server\grantType\ClientCredentials;
use nbcx\oauth\server\grantType\RefreshToken;
use nbcx\oauth\server\grantType\AuthorizationCode;
use nbcx\oauth\server\dtorage\JwtAccessToken as JwtAccessTokenStorage;
use nbcx\oauth\server\dtorage\JwtAccessTokenInterface;

/**
 * Server class for OAuth2
 * This class serves as a convience class which wraps the other Controller classes
 *
 * @see \nbcx\oauth\server\controller\ResourceController
 * @see \nbcx\oauth\server\controller\AuthorizeController
 * @see \nbcx\oauth\server\controller\TokenController
 */
class Server implements ResourceControllerInterface, AuthorizeControllerInterface, TokenControllerInterface, UserInfoControllerInterface {

    // misc properties
    protected $response;
    protected $config;
    protected $storages;

    // servers
    protected $authorizeController;
    protected $tokenController;
    protected $resourceController;
    protected $userInfoController;

    // config classes
    protected $grantTypes;
    protected $responseTypes;
    protected $tokenType;
    protected $scopeUtil;
    protected $clientAssertionType;

    protected $storageMap = [
        'access_token' => 'nbcx\oauth\server\storage\AccessTokenInterface',
        'authorization_code' => 'nbcx\oauth\server\storage\AuthorizationCodeInterface',
        'client_credentials' => 'nbcx\oauth\server\storage\ClientCredentialsInterface',
        'client' => 'nbcx\oauth\server\storage\ClientInterface',
        'refresh_token' => 'nbcx\oauth\server\storage\RefreshTokenInterface',
        'user_credentials' => 'nbcx\oauth\server\storage\UserCredentialsInterface',
        'user_claims' => 'nbcx\oauth\server\openID\storage\UserClaimsInterface',
        'public_key' => 'nbcx\oauth\server\storage\PublicKeyInterface',
        'jwt_bearer' => 'nbcx\oauth\server\storage\JWTBearerInterface',
        'scope' => 'nbcx\oauth\server\storage\ScopeInterface',
    ];

    protected $responseTypeMap = [
        'token' => 'nbcx\oauth\server\responseType\AccessTokenInterface',
        'code' => 'nbcx\oauth\server\responseType\AuthorizationCodeInterface',
        'id_token' => 'nbcx\oauth\server\openID\responseType\IdTokenInterface',
        'id_token token' => 'nbcx\oauth\server\openID\responseType\IdTokenTokenInterface',
        'code id_token' => 'nbcx\oauth\server\openID\responseType\CodeIdTokenInterface',
    ];

    /**
     * @param mixed $storage (array or \nbcx\oauth\server\storage) - single object or array of objects implementing the required storage types (ClientCredentialsInterface and AccessTokenInterface as a minimum)
     * @param array $config specify a different token lifetime, token header name, etc
     * @param array $grantTypes An array of OAuth2\GrantType\GrantTypeInterface to use for granting access tokens
     * @param array $responseTypes Response types to use.  array keys should be "code" and and "token" for
     *                                                                                     Access Token and Authorization Code response types
     * @param \nbcx\oauth\server\tokenType\TokenTypeInterface $tokenType The token type object to use. Valid token types are "bearer" and "mac"
     * @param \nbcx\oauth\server\ScopeInterface $scopeUtil The scope utility class to use to validate scope
     * @param \nbcx\oauth\server\clientAssertionType\ClientAssertionTypeInterface $clientAssertionType The method in which to verify the client identity.  Default is HttpBasic
     *
     * @ingroup oauth2_section_7
     */
    public function __construct($storage = [], array $config = [], array $grantTypes = [], array $responseTypes = [], TokenTypeInterface $tokenType = null, ScopeInterface $scopeUtil = null, ClientAssertionTypeInterface $clientAssertionType = null) {
        $storage = is_array($storage) ? $storage : [$storage];
        $this->storages = [];
        foreach ($storage as $key => $service) {
            $this->addStorage($service, $key);
        }

        // merge all config values.  These get passed to our controller objects
        $this->config = array_merge([
            'use_jwt_access_tokens' => false,
            'store_encrypted_token_string' => true,
            'use_openid_connect' => false,
            'id_lifetime' => 3600,
            'access_lifetime' => 3600,
            'www_realm' => 'Service',
            'token_param_name' => 'access_token',
            'token_bearer_header_name' => 'Bearer',
            'enforce_state' => true,
            'require_exact_redirect_uri' => true,
            'allow_implicit' => false,
            'allow_credentials_in_request_body' => true,
            'allow_public_clients' => true,
            'always_issue_new_refresh_token' => false,
            'unset_refresh_token_after_use' => true,
        ], $config);

        foreach ($grantTypes as $key => $grantType) {
            $this->addGrantType($grantType, $key);
        }

        foreach ($responseTypes as $key => $responseType) {
            $this->addResponseType($responseType, $key);
        }

        $this->tokenType = $tokenType;
        $this->scopeUtil = $scopeUtil;
        $this->clientAssertionType = $clientAssertionType;

        if ($this->config['use_openid_connect']) {
            $this->validateOpenIdConnect();
        }
    }

    public function getAuthorizeController() {
        if (is_null($this->authorizeController)) {
            $this->authorizeController = $this->createDefaultAuthorizeController();
        }

        return $this->authorizeController;
    }

    public function getTokenController() {
        if (is_null($this->tokenController)) {
            $this->tokenController = $this->createDefaultTokenController();
        }

        return $this->tokenController;
    }

    public function getResourceController() {
        if (is_null($this->resourceController)) {
            $this->resourceController = $this->createDefaultResourceController();
        }

        return $this->resourceController;
    }

    public function getUserInfoController() {
        if (is_null($this->userInfoController)) {
            $this->userInfoController = $this->createDefaultUserInfoController();
        }

        return $this->userInfoController;
    }

    /**
     * every getter deserves a setter
     */
    public function setAuthorizeController(AuthorizeControllerInterface $authorizeController) {
        $this->authorizeController = $authorizeController;
    }

    /**
     * every getter deserves a setter
     */
    public function setTokenController(TokenControllerInterface $tokenController) {
        $this->tokenController = $tokenController;
    }

    /**
     * every getter deserves a setter
     */
    public function setResourceController(ResourceControllerInterface $resourceController) {
        $this->resourceController = $resourceController;
    }

    /**
     * every getter deserves a setter
     */
    public function setUserInfoController(UserInfoControllerInterface $userInfoController) {
        $this->userInfoController = $userInfoController;
    }

    /**
     * Return claims about the authenticated end-user.
     * This would be called from the "/UserInfo" endpoint as defined in the spec.
     *
     * @param $request - OAuth2\RequestInterface
     * Request object to grant access token
     *
     * @param $response - OAuth2\ResponseInterface
     * Response object containing error messages (failure) or user claims (success)
     *
     * @throws InvalidArgumentException
     * @throws LogicException
     *
     * @see http://openid.net/specs/openid-connect-core-1_0.html#UserInfo
     */
    public function handleUserInfoRequest(RequestInterface $request, ResponseInterface $response = null) {
        $this->response = is_null($response) ? new Response() : $response;
        $this->getUserInfoController()->handleUserInfoRequest($request, $this->response);

        return $this->response;
    }

    /**
     * Grant or deny a requested access token.
     * This would be called from the "/token" endpoint as defined in the spec.
     * Obviously, you can call your endpoint whatever you want.
     *
     * @param $request - OAuth2\RequestInterface
     * Request object to grant access token
     *
     * @param $response - OAuth2\ResponseInterface
     * Response object containing error messages (failure) or access token (success)
     *
     * @throws InvalidArgumentException
     * @throws LogicException
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4
     * @see http://tools.ietf.org/html/rfc6749#section-10.6
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.3
     *
     * @ingroup oauth2_section_4
     */
    public function handleTokenRequest(RequestInterface $request, ResponseInterface $response = null) {
        $this->response = is_null($response) ? new Response() : $response;
        $this->getTokenController()->handleTokenRequest($request, $this->response);

        return $this->response;
    }

    public function grantAccessToken(RequestInterface $request, ResponseInterface $response = null) {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getTokenController()->grantAccessToken($request, $this->response);

        return $value;
    }

    /**
     * Handle a revoke token request
     * This would be called from the "/revoke" endpoint as defined in the draft Token Revocation spec
     *
     * @see https://tools.ietf.org/html/rfc7009#section-2
     *
     * @param RequestInterface $request
     * @param ResponseInterface $response
     * @return Response|ResponseInterface
     */
    public function handleRevokeRequest(RequestInterface $request, ResponseInterface $response = null) {
        $this->response = is_null($response) ? new Response() : $response;
        $this->getTokenController()->handleRevokeRequest($request, $this->response);

        return $this->response;
    }

    /**
     * Redirect the user appropriately after approval.
     *
     * After the user has approved or denied the resource request the
     * authorization server should call this function to redirect the user
     * appropriately.
     *
     * @param $request
     * The request should have the follow parameters set in the querystring:
     * - response_type: The requested response: an access token, an
     * authorization code, or both.
     * - client_id: The client identifier as described in Section 2.
     * - redirect_uri: An absolute URI to which the authorization server
     * will redirect the user-agent to when the end-user authorization
     * step is completed.
     * - scope: (optional) The scope of the resource request expressed as a
     * list of space-delimited strings.
     * - state: (optional) An opaque value used by the client to maintain
     * state between the request and callback.
     * @param $is_authorized
     * TRUE or FALSE depending on whether the user authorized the access.
     * @param $user_id
     * Identifier of user who authorized the client
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4
     *
     * @ingroup oauth2_section_4
     */
    public function handleAuthorizeRequest(RequestInterface $request, ResponseInterface $response, $is_authorized, $user_id = null) {
        $this->response = $response;
        $this->getAuthorizeController()->handleAuthorizeRequest($request, $this->response, $is_authorized, $user_id);

        return $this->response;
    }

    /**
     * Pull the authorization request data out of the HTTP request.
     * - The redirect_uri is OPTIONAL as per draft 20. But your implementation can enforce it
     * by setting $config['enforce_redirect'] to true.
     * - The state is OPTIONAL but recommended to enforce CSRF. Draft 21 states, however, that
     * CSRF protection is MANDATORY. You can enforce this by setting the $config['enforce_state'] to true.
     *
     * The draft specifies that the parameters should be retrieved from GET, override the Response
     * object to change this
     *
     * @return
     * The authorization parameters so the authorization server can prompt
     * the user for approval if valid.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4.1.1
     * @see http://tools.ietf.org/html/rfc6749#section-10.12
     *
     * @ingroup oauth2_section_3
     */
    public function validateAuthorizeRequest(RequestInterface $request, ResponseInterface $response = null) {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getAuthorizeController()->validateAuthorizeRequest($request, $this->response);

        return $value;
    }

    public function verifyResourceRequest(RequestInterface $request, ResponseInterface $response = null, $scope = null) {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getResourceController()->verifyResourceRequest($request, $this->response, $scope);

        return $value;
    }

    public function getAccessTokenData(RequestInterface $request, ResponseInterface $response = null) {
        $this->response = is_null($response) ? new Response() : $response;
        $value = $this->getResourceController()->getAccessTokenData($request, $this->response);

        return $value;
    }

    public function addGrantType(GrantTypeInterface $grantType, $identifier = null) {
        if (!is_string($identifier)) {
            $identifier = $grantType->getQuerystringIdentifier();
        }

        $this->grantTypes[$identifier] = $grantType;

        // persist added grant type down to TokenController
        if (!is_null($this->tokenController)) {
            $this->getTokenController()->addGrantType($grantType, $identifier);
        }
    }

    /**
     * Set a storage object for the server
     *
     * @param $storage
     * An object implementing one of the Storage interfaces
     * @param $key
     * If null, the storage is set to the key of each storage interface it implements
     *
     * @see storageMap
     */
    public function addStorage($storage, $key = null) {
        // if explicitly set to a valid key, do not "magically" set below
        if (isset($this->storageMap[$key])) {
            if (!is_null($storage) && !$storage instanceof $this->storageMap[$key]) {
                throw new \InvalidArgumentException(sprintf('storage of type "%s" must implement interface "%s"', $key, $this->storageMap[$key]));
            }
            $this->storages[$key] = $storage;

            // special logic to handle "client" and "client_credentials" strangeness
            if ($key === 'client' && !isset($this->storages['client_credentials'])) {
                if ($storage instanceof \OAuth2\Storage\ClientCredentialsInterface) {
                    $this->storages['client_credentials'] = $storage;
                }
            }
            elseif ($key === 'client_credentials' && !isset($this->storages['client'])) {
                if ($storage instanceof \OAuth2\Storage\ClientInterface) {
                    $this->storages['client'] = $storage;
                }
            }
        }
        elseif (!is_null($key) && !is_numeric($key)) {
            throw new \InvalidArgumentException(sprintf('unknown storage key "%s", must be one of [%s]', $key, implode(', ', array_keys($this->storageMap))));
        }
        else {
            $set = false;
            foreach ($this->storageMap as $type => $interface) {
                if ($storage instanceof $interface) {
                    $this->storages[$type] = $storage;
                    $set = true;
                }
            }

            if (!$set) {
                throw new \InvalidArgumentException(sprintf('storage of class "%s" must implement one of [%s]', get_class($storage), implode(', ', $this->storageMap)));
            }
        }
    }

    public function addResponseType(ResponseTypeInterface $responseType, $key = null) {
        $key = $this->normalizeResponseType($key);

        if (isset($this->responseTypeMap[$key])) {
            if (!$responseType instanceof $this->responseTypeMap[$key]) {
                throw new \InvalidArgumentException(sprintf('responseType of type "%s" must implement interface "%s"', $key, $this->responseTypeMap[$key]));
            }
            $this->responseTypes[$key] = $responseType;
        }
        elseif (!is_null($key) && !is_numeric($key)) {
            throw new \InvalidArgumentException(sprintf('unknown responseType key "%s", must be one of [%s]', $key, implode(', ', array_keys($this->responseTypeMap))));
        }
        else {
            $set = false;
            foreach ($this->responseTypeMap as $type => $interface) {
                if ($responseType instanceof $interface) {
                    $this->responseTypes[$type] = $responseType;
                    $set = true;
                }
            }

            if (!$set) {
                throw new \InvalidArgumentException(sprintf('Unknown response type %s.  Please implement one of [%s]', get_class($responseType), implode(', ', $this->responseTypeMap)));
            }
        }
    }

    public function getScopeUtil() {
        if (!$this->scopeUtil) {
            $storage = isset($this->storages['scope']) ? $this->storages['scope'] : null;
            $this->scopeUtil = new Scope($storage);
        }

        return $this->scopeUtil;
    }

    /**
     * every getter deserves a setter
     */
    public function setScopeUtil($scopeUtil) {
        $this->scopeUtil = $scopeUtil;
    }

    protected function createDefaultAuthorizeController() {
        if (!isset($this->storages['client'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\ClientInterface to use the authorize server");
        }
        if (0 == count($this->responseTypes)) {
            $this->responseTypes = $this->getDefaultResponseTypes();
        }
        if ($this->config['use_openid_connect'] && !isset($this->responseTypes['id_token'])) {
            $this->responseTypes['id_token'] = $this->createDefaultIdTokenResponseType();
            if ($this->config['allow_implicit']) {
                $this->responseTypes['id_token token'] = $this->createDefaultIdTokenTokenResponseType();
            }
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'allow_implicit enforce_state require_exact_redirect_uri')));

        if ($this->config['use_openid_connect']) {
            return new OpenIDAuthorizeController($this->storages['client'], $this->responseTypes, $config, $this->getScopeUtil());
        }

        return new AuthorizeController($this->storages['client'], $this->responseTypes, $config, $this->getScopeUtil());
    }

    protected function createDefaultTokenController() {
        if (0 == count($this->grantTypes)) {
            $this->grantTypes = $this->getDefaultGrantTypes();
        }

        if (is_null($this->clientAssertionType)) {
            // see if HttpBasic assertion type is requred.  If so, then create it from storage classes.
            foreach ($this->grantTypes as $grantType) {
                if (!$grantType instanceof ClientAssertionTypeInterface) {
                    if (!isset($this->storages['client_credentials'])) {
                        throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\ClientCredentialsInterface to use the token server");
                    }
                    $config = array_intersect_key($this->config, array_flip(explode(' ', 'allow_credentials_in_request_body allow_public_clients')));
                    $this->clientAssertionType = new HttpBasic($this->storages['client_credentials'], $config);
                    break;
                }
            }
        }

        if (!isset($this->storages['client'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\ClientInterface to use the token server");
        }

        $accessTokenResponseType = $this->getAccessTokenResponseType();

        return new TokenController($accessTokenResponseType, $this->storages['client'], $this->grantTypes, $this->clientAssertionType, $this->getScopeUtil());
    }

    protected function createDefaultResourceController() {
        if ($this->config['use_jwt_access_tokens']) {
            // overwrites access token storage with crypto token storage if "use_jwt_access_tokens" is set
            if (!isset($this->storages['access_token']) || !$this->storages['access_token'] instanceof JwtAccessTokenInterface) {
                $this->storages['access_token'] = $this->createDefaultJwtAccessTokenStorage();
            }
        }
        elseif (!isset($this->storages['access_token'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\AccessTokenInterface or use JwtAccessTokens to use the resource server");
        }

        if (!$this->tokenType) {
            $this->tokenType = $this->getDefaultTokenType();
        }

        $config = array_intersect_key($this->config, ['www_realm' => '']);

        return new ResourceController($this->tokenType, $this->storages['access_token'], $config, $this->getScopeUtil());
    }

    protected function createDefaultUserInfoController() {
        if ($this->config['use_jwt_access_tokens']) {
            // overwrites access token storage with crypto token storage if "use_jwt_access_tokens" is set
            if (!isset($this->storages['access_token']) || !$this->storages['access_token'] instanceof JwtAccessTokenInterface) {
                $this->storages['access_token'] = $this->createDefaultJwtAccessTokenStorage();
            }
        }
        elseif (!isset($this->storages['access_token'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\AccessTokenInterface or use JwtAccessTokens to use the UserInfo server");
        }

        if (!isset($this->storages['user_claims'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\OpenID\Storage\UserClaimsInterface to use the UserInfo server");
        }

        if (!$this->tokenType) {
            $this->tokenType = $this->getDefaultTokenType();
        }

        $config = array_intersect_key($this->config, ['www_realm' => '']);

        return new UserInfoController($this->tokenType, $this->storages['access_token'], $this->storages['user_claims'], $config, $this->getScopeUtil());
    }

    protected function getDefaultTokenType() {
        $config = array_intersect_key($this->config, array_flip(explode(' ', 'token_param_name token_bearer_header_name')));

        return new Bearer($config);
    }

    protected function getDefaultResponseTypes() {
        $responseTypes = [];

        if ($this->config['allow_implicit']) {
            $responseTypes['token'] = $this->getAccessTokenResponseType();
        }

        if ($this->config['use_openid_connect']) {
            $responseTypes['id_token'] = $this->getIdTokenResponseType();
            if ($this->config['allow_implicit']) {
                $responseTypes['id_token token'] = $this->getIdTokenTokenResponseType();
            }
        }

        if (isset($this->storages['authorization_code'])) {
            $config = array_intersect_key($this->config, array_flip(explode(' ', 'enforce_redirect auth_code_lifetime')));
            if ($this->config['use_openid_connect']) {
                if (!$this->storages['authorization_code'] instanceof OpenIDAuthorizationCodeInterface) {
                    throw new \LogicException("Your authorization_code storage must implement OAuth2\OpenID\Storage\AuthorizationCodeInterface to work when 'use_openid_connect' is true");
                }
                $responseTypes['code'] = new OpenIDAuthorizationCodeResponseType($this->storages['authorization_code'], $config);
                $responseTypes['code id_token'] = new CodeIdToken($responseTypes['code'], $responseTypes['id_token']);
            }
            else {
                $responseTypes['code'] = new AuthorizationCodeResponseType($this->storages['authorization_code'], $config);
            }
        }

        if (count($responseTypes) == 0) {
            throw new \LogicException("You must supply an array of response_types in the constructor or implement a OAuth2\Storage\AuthorizationCodeInterface storage object or set 'allow_implicit' to true and implement a OAuth2\Storage\AccessTokenInterface storage object");
        }

        return $responseTypes;
    }

    protected function getDefaultGrantTypes() {
        $grantTypes = [];

        if (isset($this->storages['user_credentials'])) {
            $grantTypes['password'] = new UserCredentials($this->storages['user_credentials']);
        }

        if (isset($this->storages['client_credentials'])) {
            $config = array_intersect_key($this->config, ['allow_credentials_in_request_body' => '']);
            $grantTypes['client_credentials'] = new ClientCredentials($this->storages['client_credentials'], $config);
        }

        if (isset($this->storages['refresh_token'])) {
            $config = array_intersect_key($this->config, array_flip(explode(' ', 'always_issue_new_refresh_token unset_refresh_token_after_use')));
            $grantTypes['refresh_token'] = new RefreshToken($this->storages['refresh_token'], $config);
        }

        if (isset($this->storages['authorization_code'])) {
            if ($this->config['use_openid_connect']) {
                if (!$this->storages['authorization_code'] instanceof OpenIDAuthorizationCodeInterface) {
                    throw new \LogicException("Your authorization_code storage must implement OAuth2\OpenID\Storage\AuthorizationCodeInterface to work when 'use_openid_connect' is true");
                }
                $grantTypes['authorization_code'] = new OpenIDAuthorizationCodeGrantType($this->storages['authorization_code']);
            }
            else {
                $grantTypes['authorization_code'] = new AuthorizationCode($this->storages['authorization_code']);
            }
        }

        if (count($grantTypes) == 0) {
            throw new \LogicException("Unable to build default grant types - You must supply an array of grant_types in the constructor");
        }

        return $grantTypes;
    }

    protected function getAccessTokenResponseType() {
        if (isset($this->responseTypes['token'])) {
            return $this->responseTypes['token'];
        }

        if ($this->config['use_jwt_access_tokens']) {
            return $this->createDefaultJwtAccessTokenResponseType();
        }

        return $this->createDefaultAccessTokenResponseType();
    }

    protected function getIdTokenResponseType() {
        if (isset($this->responseTypes['id_token'])) {
            return $this->responseTypes['id_token'];
        }

        return $this->createDefaultIdTokenResponseType();
    }

    protected function getIdTokenTokenResponseType() {
        if (isset($this->responseTypes['id_token token'])) {
            return $this->responseTypes['id_token token'];
        }

        return $this->createDefaultIdTokenTokenResponseType();
    }

    /**
     * For Resource Controller
     */
    protected function createDefaultJwtAccessTokenStorage() {
        if (!isset($this->storages['public_key'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\PublicKeyInterface to use crypto tokens");
        }
        $tokenStorage = null;
        if (!empty($this->config['store_encrypted_token_string']) && isset($this->storages['access_token'])) {
            $tokenStorage = $this->storages['access_token'];
        }
        // wrap the access token storage as required.
        return new JwtAccessTokenStorage($this->storages['public_key'], $tokenStorage);
    }

    /**
     * For Authorize and Token Controllers
     */
    protected function createDefaultJwtAccessTokenResponseType() {
        if (!isset($this->storages['public_key'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\PublicKeyInterface to use crypto tokens");
        }

        $tokenStorage = null;
        if (isset($this->storages['access_token'])) {
            $tokenStorage = $this->storages['access_token'];
        }

        $refreshStorage = null;
        if (isset($this->storages['refresh_token'])) {
            $refreshStorage = $this->storages['refresh_token'];
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'store_encrypted_token_string issuer access_lifetime refresh_token_lifetime')));

        return new JwtAccessToken($this->storages['public_key'], $tokenStorage, $refreshStorage, $config);
    }

    protected function createDefaultAccessTokenResponseType() {
        if (!isset($this->storages['access_token'])) {
            throw new \LogicException("You must supply a response type implementing OAuth2\ResponseType\AccessTokenInterface, or a storage object implementing OAuth2\Storage\AccessTokenInterface to use the token server");
        }

        $refreshStorage = null;
        if (isset($this->storages['refresh_token'])) {
            $refreshStorage = $this->storages['refresh_token'];
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'access_lifetime refresh_token_lifetime')));
        $config['token_type'] = $this->tokenType ? $this->tokenType->getTokenType() : $this->getDefaultTokenType()->getTokenType();

        return new AccessToken($this->storages['access_token'], $refreshStorage, $config);
    }

    protected function createDefaultIdTokenResponseType() {
        if (!isset($this->storages['user_claims'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\OpenID\Storage\UserClaimsInterface to use openid connect");
        }
        if (!isset($this->storages['public_key'])) {
            throw new \LogicException("You must supply a storage object implementing OAuth2\Storage\PublicKeyInterface to use openid connect");
        }

        $config = array_intersect_key($this->config, array_flip(explode(' ', 'issuer id_lifetime')));

        return new IdToken($this->storages['user_claims'], $this->storages['public_key'], $config);
    }

    protected function createDefaultIdTokenTokenResponseType() {
        return new IdTokenToken($this->getAccessTokenResponseType(), $this->getIdTokenResponseType());
    }

    protected function validateOpenIdConnect() {
        $authCodeGrant = $this->getGrantType('authorization_code');
        if (!empty($authCodeGrant) && !$authCodeGrant instanceof OpenIDAuthorizationCodeGrantType) {
            throw new \InvalidArgumentException('You have enabled OpenID Connect, but supplied a grant type that does not support it.');
        }
    }

    protected function normalizeResponseType($name) {
        // for multiple-valued response types - make them alphabetical
        if (!empty($name) && false !== strpos($name, ' ')) {
            $types = explode(' ', $name);
            sort($types);
            $name = implode(' ', $types);
        }

        return $name;
    }

    public function getResponse() {
        return $this->response;
    }

    public function getStorages() {
        return $this->storages;
    }

    public function getStorage($name) {
        return isset($this->storages[$name]) ? $this->storages[$name] : null;
    }

    public function getGrantTypes() {
        return $this->grantTypes;
    }

    public function getGrantType($name) {
        return isset($this->grantTypes[$name]) ? $this->grantTypes[$name] : null;
    }

    public function getResponseTypes() {
        return $this->responseTypes;
    }

    public function getResponseType($name) {
        // for multiple-valued response types - make them alphabetical
        $name = $this->normalizeResponseType($name);

        return isset($this->responseTypes[$name]) ? $this->responseTypes[$name] : null;
    }

    public function getTokenType() {
        return $this->tokenType;
    }

    public function getClientAssertionType() {
        return $this->clientAssertionType;
    }

    public function setConfig($name, $value) {
        $this->config[$name] = $value;
    }

    public function getConfig($name, $default = null) {
        return isset($this->config[$name]) ? $this->config[$name] : $default;
    }
}
