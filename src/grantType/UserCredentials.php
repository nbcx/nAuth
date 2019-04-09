<?php
namespace nbcx\oauth\server\grantType;

use nbcx\oauth\server\storage\UserCredentialsInterface;
use nbcx\oauth\server\responseType\AccessTokenInterface;
use nbcx\oauth\server\RequestInterface;
use nbcx\oauth\server\ResponseInterface;

class UserCredentials implements GrantTypeInterface {

    private $userInfo;

    protected $storage;

    /**
     * @param nbcx\oauth\server\storage\UserCredentialsInterface $storage REQUIRED Storage class for retrieving user credentials information
     */
    public function __construct(UserCredentialsInterface $storage) {
        $this->storage = $storage;
    }

    public function getQuerystringIdentifier() {
        return 'password';
    }

    public function validateRequest(RequestInterface $request, ResponseInterface $response) {
        if (!$request->request("password") || !$request->request("username")) {
            $response->setError(400, 'invalid_request', 'Missing parameters: "username" and "password" required');

            return null;
        }

        if (!$this->storage->checkUserCredentials($request->request("username"), $request->request("password"))) {
            $response->setError(401, 'invalid_grant', 'Invalid username and password combination');

            return null;
        }

        $userInfo = $this->storage->getUserDetails($request->request("username"));

        if (empty($userInfo)) {
            $response->setError(400, 'invalid_grant', 'Unable to retrieve user information');

            return null;
        }

        if (!isset($userInfo['user_id'])) {
            throw new \LogicException("you must set the user_id on the array returned by getUserDetails");
        }

        $this->userInfo = $userInfo;

        return true;
    }

    public function getClientId() {
        return null;
    }

    public function getUserId() {
        return $this->userInfo['user_id'];
    }

    public function getScope() {
        return isset($this->userInfo['scope']) ? $this->userInfo['scope'] : null;
    }

    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope) {
        return $accessToken->createAccessToken($client_id, $user_id, $scope);
    }
}
