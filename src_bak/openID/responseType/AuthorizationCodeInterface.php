<?php
namespace nbcx\oauth\server\OpenID\ResponseType;

use nbcx\oauth\server\responseType\AuthorizationCodeInterface as BaseAuthorizationCodeInterface;

interface AuthorizationCodeInterface extends BaseAuthorizationCodeInterface {
    /**
     * Handle the creation of the authorization code.
     *
     * @param $client_id                Client identifier related to the authorization code
     * @param $user_id                  User ID associated with the authorization code
     * @param $redirect_uri             An absolute URI to which the authorization server will redirect the
     *                                  user-agent to when the end-user authorization step is completed.
     * @param $scope        OPTIONAL    Scopes to be stored in space-separated string.
     * @param $id_token     OPTIONAL    The OpenID Connect id_token.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4
     * @ingroup oauth2_section_4
     */
    public function createAuthorizationCode($client_id, $user_id, $redirect_uri, $scope = null, $id_token = null);
}
