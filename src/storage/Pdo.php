<?php
namespace nbcx\oauth\server\storage;

use nbcx\oauth\server\openID\storage\UserClaimsInterface;
use nbcx\oauth\server\openID\storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;

class Pdo implements
    AuthorizationCodeInterface,
    AccessTokenInterface,
    ClientCredentialsInterface,
    UserCredentialsInterface,
    RefreshTokenInterface,
    JwtBearerInterface,
    ScopeInterface,
    PublicKeyInterface,
    UserClaimsInterface,
    OpenIDAuthorizationCodeInterface {

    protected $db;
    protected $config;

    public function __construct($connection, $config = []) {
        if (!$connection instanceof \PDO) {
            if (is_string($connection)) {
                $connection = ['dsn' => $connection];
            }
            if (!is_array($connection)) {
                throw new \InvalidArgumentException('First argument to OAuth2\Storage\Pdo must be an instance of PDO, a DSN string, or a configuration array');
            }
            if (!isset($connection['dsn'])) {
                throw new \InvalidArgumentException('configuration array must contain "dsn"');
            }
            // merge optional parameters
            $connection = array_merge([
                'username' => null,
                'password' => null,
                'options' => [],
            ], $connection);
            $connection = new \PDO($connection['dsn'], $connection['username'], $connection['password'], $connection['options']);
        }
        $this->db = $connection;

        // debugging
        $connection->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        $this->config = array_merge([
            'client_table' => 'oauth_clients',
            'access_token_table' => 'oauth_access_tokens',
            'refresh_token_table' => 'oauth_refresh_tokens',
            'code_table' => 'oauth_authorization_codes',
            'user_table' => 'oauth_users',
            'jwt_table' => 'oauth_jwt',
            'jti_table' => 'oauth_jti',
            'scope_table' => 'oauth_scopes',
            'public_key_table' => 'oauth_public_keys',
        ], $config);
    }

    /**
     * @param $sql
     * @param null $params
     * @param bool $isselect 是否是查询语句
     * @return int|\PDOStatement
     * @throws \Exception
     */
    public function execute($table, $sql, $params = NULL,$isselect=false) {
        $sql = sprintf($sql,$table);

        if($params !== null && !is_array($params)) {
            $params = [$params];
        }
        \nb\Debug::record(3, $sql, $params);

        $db = $this->db->prepare($sql);

        $result = is_null($params) ? $db->execute() : $db->execute($params);
        if (false !== $result) {
            return $isselect?$db:$db->rowCount();
        }
        $error = $db->errorInfo();
        if(isset($error[2])) {
            $error = "[{$error[0]}][{$error[1]}]{$error[2]}";
        }
        else {
            $error = $sql.': '.json_encode($params);
        }

        throw new \Exception($error);
    }

    public function select($table, $sql, $params = NULL,$isStmt = false) {
        $stmt = $this->execute($table, $sql, $params,true);
        return $isStmt?$stmt:$stmt->fetch(\PDO::FETCH_ASSOC);
    }

    /* OAuth2\Storage\ClientCredentialsInterface */
    public function checkClientCredentials($client_id, $client_secret = null) {

        $result = $this->select($this->config['client_table'],'SELECT * from %s where client_id = ?',$client_id);
        return $result && $result['client_secret'] == $client_secret;

        #TODO delete
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where client_id = :client_id', $this->config['client_table']));
        $stmt->execute(compact('client_id'));
        $result = $stmt->fetch(\PDO::FETCH_ASSOC);

        // make this extensible
        return $result && $result['client_secret'] == $client_secret;
    }

    public function isPublicClient($client_id) {
        $result = $this->select($this->config['client_table'], 'SELECT * from %s where client_id = ?',$client_id);
        if (!$result) {
            return false;
        }
        return empty($result['client_secret']);

        #TODO delete
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where client_id = :client_id', $this->config['client_table']));
        $stmt->execute(compact('client_id'));

        if (!$result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return false;
        }

        return empty($result['client_secret']);
    }

    /* OAuth2\Storage\ClientInterface */
    public function getClientDetails($client_id) {

        $result = $this->select($this->config['client_table'],'SELECT * from %s where client_id = ?',$client_id);
        return $result;

        #TODO delete
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where client_id = :client_id', $this->config['client_table']));
        $stmt->execute(compact('client_id'));

        return $stmt->fetch(\PDO::FETCH_ASSOC);
    }

    public function setClientDetails($client_id, $client_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null) {
        $data = [
            $client_id,
            $client_secret,
            $redirect_uri,
            $grant_types,
            $scope,
            $user_id
        ];

        // if it exists, update it.
        if ($this->getClientDetails($client_id)) {
            $result = $this->execute($this->config['client_table'],'UPDATE %s SET client_secret=?, redirect_uri=?, grant_types=?, scope=?, user_id=? where client_id=?',$data);
        }
        else {
            $result = $this->execute($this->config['client_table'],'INSERT INTO %s (client_id, client_secret, redirect_uri, grant_types, scope, user_id) VALUES (?, ?, ?, ?, ?, ?)', $data);
        }

        return $result;

        #TODO delete
        // if it exists, update it.
        if ($this->getClientDetails($client_id)) {
            $stmt = $this->db->prepare($sql = sprintf('UPDATE %s SET client_secret=:client_secret, redirect_uri=:redirect_uri, grant_types=:grant_types, scope=:scope, user_id=:user_id where client_id=:client_id', $this->config['client_table']));
        }
        else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (client_id, client_secret, redirect_uri, grant_types, scope, user_id) VALUES (:client_id, :client_secret, :redirect_uri, :grant_types, :scope, :user_id)', $this->config['client_table']));
        }

        return $stmt->execute(compact('client_id', 'client_secret', 'redirect_uri', 'grant_types', 'scope', 'user_id'));
    }

    public function checkRestrictedGrantType($client_id, $grant_type) {
        $details = $this->getClientDetails($client_id);
        if (isset($details['grant_types'])) {
            $grant_types = explode(' ', $details['grant_types']);

            return in_array($grant_type, (array)$grant_types);
        }

        // if grant_types are not defined, then none are restricted
        return true;
    }

    /* OAuth2\Storage\AccessTokenInterface */
    public function getAccessToken($access_token) {
        $token = $this->select($this->config['access_token_table'], 'SELECT * from ? where access_token = ?',$access_token);
        if ($token) {
            // convert date string back to timestamp
            $token['expires'] = strtotime($token['expires']);
        }

        return $token;

        #TODO delete
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where access_token = :access_token', $this->config['access_token_table']));

        $token = $stmt->execute(compact('access_token'));
        if ($token = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            // convert date string back to timestamp
            $token['expires'] = strtotime($token['expires']);
        }

        return $token;
    }

    public function setAccessToken($access_token, $client_id, $user_id, $expires, $scope = null) {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);
        $data = [
            $client_id,
            $expires,
            $user_id,
            $scope,
            $access_token
        ];
        if ($this->getAccessToken($access_token)) {
            $result = $this->execute($this->config['access_token_table'], 'UPDATE %s SET client_id=?, expires=?, user_id=?, scope=? where access_token=?', $data);
        }
        else {
            $result = $this->execute($this->config['access_token_table'], 'INSERT INTO %s (client_id, expires, user_id, scope, access_token) VALUES (?, ?, ?, ?, ?)',$data);
        }
        return $result;

        #TODO delete
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAccessToken($access_token)) {
            $stmt = $this->db->prepare(sprintf('UPDATE %s SET client_id=:client_id, expires=:expires, user_id=:user_id, scope=:scope where access_token=:access_token', $this->config['access_token_table']));
        }
        else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (access_token, client_id, expires, user_id, scope) VALUES (:access_token, :client_id, :expires, :user_id, :scope)', $this->config['access_token_table']));
        }

        return $stmt->execute(compact('access_token', 'client_id', 'user_id', 'expires', 'scope'));
    }

    public function unsetAccessToken($access_token) {
        return $this->execute(
            $this->config['access_token_table'],
            'DELETE FROM %s WHERE access_token = ?',
            $access_token
        );

        #TODO delete
        $stmt = $this->db->prepare(sprintf('DELETE FROM %s WHERE access_token = :access_token', $this->config['access_token_table']));

        return $stmt->execute(compact('access_token'));
    }

    /* OAuth2\Storage\AuthorizationCodeInterface */
    public function getAuthorizationCode($code) {

        return $this->select($this->config['code_table'],'SELECT * from ? where authorization_code = ?',$code);

        #TODO delete
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where authorization_code = :code', $this->config['code_table']));
        $stmt->execute(compact('code'));

        if ($code = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            // convert date string back to timestamp
            $code['expires'] = strtotime($code['expires']);
        }

        return $code;
    }

    public function setAuthorizationCode($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null) {
        if (func_num_args() > 6) {
            // we are calling with an id token
            return call_user_func_array([$this, 'setAuthorizationCodeWithIdToken'], func_get_args());
        }

        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        $data = [
            $client_id,
            $user_id,
            $redirect_uri,
            $expires,
            $scope
        ];
        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $result = $this->execute($this->config['code_table'],'UPDATE %s SET client_id=?, user_id=?, redirect_uri=?, expires=?, scope=? where authorization_code=?',$data);
        }
        else {
            $result = $this->execute($this->config['code_table'],'INSERT INTO %s (client_id, user_id, redirect_uri, expires, scope, authorization_code) VALUES (?, ?, ?, ?, ?, ?)',$data);
        }

        return $result;



        #TODO delete
        if (func_num_args() > 6) {
            // we are calling with an id token
            return call_user_func_array([$this, 'setAuthorizationCodeWithIdToken'], func_get_args());
        }

        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $stmt = $this->db->prepare($sql = sprintf('UPDATE %s SET client_id=:client_id, user_id=:user_id, redirect_uri=:redirect_uri, expires=:expires, scope=:scope where authorization_code=:code', $this->config['code_table']));
        }
        else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (authorization_code, client_id, user_id, redirect_uri, expires, scope) VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope)', $this->config['code_table']));
        }

        return $stmt->execute(compact('code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope'));
    }

    private function setAuthorizationCodeWithIdToken($code, $client_id, $user_id, $redirect_uri, $expires, $scope = null, $id_token = null) {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);
        $data = [
            $client_id,
            $user_id,
            $redirect_uri,
            $expires,
            $scope,
            $id_token
        ];
        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $result = $this->execute($this->config['code_table'],'UPDATE %s SET client_id=?, user_id=?, redirect_uri=?, expires=?, scope=?, id_token =? where authorization_code=?',$data);
        }
        else {
            $result = $this->execute($this->config['code_table'],'INSERT INTO %s (client_id, user_id, redirect_uri, expires, scope, id_token, authorization_code) VALUES (?, ?, ?, ?, ?, ?, ?)',$data);
        }

        return $result;


        #TODO delete

        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $stmt = $this->db->prepare($sql = sprintf('UPDATE %s SET client_id=:client_id, user_id=:user_id, redirect_uri=:redirect_uri, expires=:expires, scope=:scope, id_token =:id_token where authorization_code=:code', $this->config['code_table']));
        }
        else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (authorization_code, client_id, user_id, redirect_uri, expires, scope, id_token) VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope, :id_token)', $this->config['code_table']));
        }

        return $stmt->execute(compact('code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope', 'id_token'));
    }

    public function expireAuthorizationCode($code) {

        return $this->execute($this->config['code_table'],'DELETE FROM %s WHERE authorization_code = ?',[
            $code
        ]);

        #TODO delete
        $stmt = $this->db->prepare(sprintf('DELETE FROM %s WHERE authorization_code = :code', $this->config['code_table']));

        return $stmt->execute(compact('code'));
    }

    /* OAuth2\Storage\UserCredentialsInterface */
    public function checkUserCredentials($username, $password) {
        if ($user = $this->getUser($username)) {
            return $this->checkPassword($user, $password);
        }

        return false;
    }

    public function getUserDetails($username) {
        return $this->getUser($username);
    }

    /* UserClaimsInterface */
    public function getUserClaims($user_id, $claims) {
        if (!$userDetails = $this->getUserDetails($user_id)) {
            return false;
        }

        $claims = explode(' ', trim($claims));
        $userClaims = [];

        // for each requested claim, if the user has the claim, set it in the response
        $validClaims = explode(' ', self::VALID_CLAIMS);
        foreach ($validClaims as $validClaim) {
            if (in_array($validClaim, $claims)) {
                if ($validClaim == 'address') {
                    // address is an object with subfields
                    $userClaims['address'] = $this->getUserClaim($validClaim, $userDetails['address'] ?: $userDetails);
                }
                else {
                    $userClaims = array_merge($userClaims, $this->getUserClaim($validClaim, $userDetails));
                }
            }
        }

        return $userClaims;
    }

    protected function getUserClaim($claim, $userDetails) {
        $userClaims = [];
        $claimValuesString = constant(sprintf('self::%s_CLAIM_VALUES', strtoupper($claim)));
        $claimValues = explode(' ', $claimValuesString);

        foreach ($claimValues as $value) {
            $userClaims[$value] = isset($userDetails[$value]) ? $userDetails[$value] : null;
        }

        return $userClaims;
    }

    /* OAuth2\Storage\RefreshTokenInterface */
    public function getRefreshToken($refresh_token) {
        $token = $this->select( $this->config['refresh_token_table'],'SELECT * FROM %s WHERE refresh_token = ?',[
            $refresh_token
        ]);
        // convert expires to epoch time
        $token and $token['expires'] = strtotime($token['expires']);

        return $token;

        #TODO delete
        $stmt = $this->db->prepare(sprintf('SELECT * FROM %s WHERE refresh_token = :refresh_token', $this->config['refresh_token_table']));

        $token = $stmt->execute(compact('refresh_token'));
        if ($token = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            // convert expires to epoch time
            $token['expires'] = strtotime($token['expires']);
        }

        return $token;
    }

    public function setRefreshToken($refresh_token, $client_id, $user_id, $expires, $scope = null) {
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);
        $result = $this->select($this->config['refresh_token_table'],'INSERT INTO %s (refresh_token, client_id, user_id, expires, scope) VALUES (?, ?, ?, ?, ?)',[
            $refresh_token,
            $client_id,
            $user_id,
            $expires,
            $scope
        ]);
        return $result;

        #TODO delete
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        $stmt = $this->db->prepare(sprintf('INSERT INTO %s (refresh_token, client_id, user_id, expires, scope) VALUES (:refresh_token, :client_id, :user_id, :expires, :scope)', $this->config['refresh_token_table']));

        return $stmt->execute(compact('refresh_token', 'client_id', 'user_id', 'expires', 'scope'));
    }

    public function unsetRefreshToken($refresh_token) {
        return $this->execute($this->config['refresh_token_table'],'DELETE FROM %s WHERE refresh_token = ?',[
            $refresh_token
        ]);

        #TODO delete
        $stmt = $this->db->prepare(sprintf('DELETE FROM %s WHERE refresh_token = :refresh_token', $this->config['refresh_token_table']));

        return $stmt->execute(compact('refresh_token'));
    }

    // plaintext passwords are bad!  Override this for your application
    protected function checkPassword($user, $password) {
        return $user['password'] == sha1($password);
    }

    public function getUser($username) {

        $userInfo = $this->select($this->config['user_table'], 'SELECT * from %s where username=?',[
            $username
        ]);
        if (!$userInfo) {
            return false;
        }

        // the default behavior is to use "username" as the user_id
        return array_merge([
            'user_id' => $username
        ], $userInfo);

        #TODO delete
        $stmt = $this->db->prepare($sql = sprintf('SELECT * from %s where username=:username', $this->config['user_table']));
        $stmt->execute(['username' => $username]);

        if (!$userInfo = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return false;
        }

        // the default behavior is to use "username" as the user_id
        return array_merge([
            'user_id' => $username
        ], $userInfo);
    }

    public function setUser($username, $password, $firstName = null, $lastName = null) {
        // do not store in plaintext
        $password = sha1($password);
        $data = [
            $password,
            $firstName,
            $lastName
        ];
        if ($this->getUser($username)) {
            $result = $this->execute( $this->config['user_table'],'UPDATE %s SET password=?, first_name=?, last_name=? where username=?',$data);
        }
        else {
            $result = $this->execute( $this->config['user_table'],'INSERT INTO %s (password, first_name, last_name, username) VALUES (?, ?, ?, ?)',$data);
        }
        return $result;

        #TODO delete
        // do not store in plaintext
        $password = sha1($password);

        // if it exists, update it.
        if ($this->getUser($username)) {
            $stmt = $this->db->prepare($sql = sprintf('UPDATE %s SET password=:password, first_name=:firstName, last_name=:lastName where username=:username', $this->config['user_table']));
        }
        else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (username, password, first_name, last_name) VALUES (:username, :password, :firstName, :lastName)', $this->config['user_table']));
        }

        return $stmt->execute(compact('username', 'password', 'firstName', 'lastName'));
    }

    /* ScopeInterface */
    public function scopeExists($scope) {
        $scope = explode(' ', $scope);
        $whereIn = implode(',', array_fill(0, count($scope), '?'));
        $result = $this->select( $this->config['scope_table'],'SELECT count(scope) as count FROM %s WHERE scope IN ('.$whereIn.')', $scope);

        if ($result) {
            return $result['count'] == count($scope);
        }

        return false;

        #TODO delete
        $scope = explode(' ', $scope);
        $whereIn = implode(',', array_fill(0, count($scope), '?'));
        $stmt = $this->db->prepare(sprintf('SELECT count(scope) as count FROM %s WHERE scope IN (%s)', $this->config['scope_table'], $whereIn));
        $stmt->execute($scope);

        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['count'] == count($scope);
        }

        return false;
    }

    public function getDefaultScope($client_id = null) {
        $result = $this->select($this->config['scope_table'],'SELECT scope FROM %s WHERE is_default=?',[
            true
        ]);
        if ($result) {
            $defaultScope = array_map(function ($row) {
                return $row['scope'];
            }, $result);

            return implode(' ', $defaultScope);
        }

        return null;

        #TODO delete
        $stmt = $this->db->prepare(sprintf('SELECT scope FROM %s WHERE is_default=:is_default', $this->config['scope_table']));
        $stmt->execute(['is_default' => true]);

        if ($result = $stmt->fetchAll(\PDO::FETCH_ASSOC)) {
            $defaultScope = array_map(function ($row) {
                return $row['scope'];
            }, $result);

            return implode(' ', $defaultScope);
        }

        return null;
    }

    /* JWTBearerInterface */
    public function getClientKey($client_id, $subject) {
        $stmt = $this->select( $this->config['jwt_table'],'SELECT public_key from %s where client_id=? AND subject=?',[
            $client_id,
            $subject
        ],true);
        return $stmt->fetchColumn();

        #TODO delete
        $stmt = $this->db->prepare($sql = sprintf('SELECT public_key from %s where client_id=:client_id AND subject=:subject', $this->config['jwt_table']));

        $stmt->execute(['client_id' => $client_id, 'subject' => $subject]);

        return $stmt->fetchColumn();
    }

    public function getClientScope($client_id) {
        if (!$clientDetails = $this->getClientDetails($client_id)) {
            return false;
        }

        if (isset($clientDetails['scope'])) {
            return $clientDetails['scope'];
        }

        return null;
    }

    public function getJti($client_id, $subject, $audience, $expires, $jti) {
        $result = $this->execute( $this->config['jti_table'],'SELECT * FROM %s WHERE issuer=? AND subject=? AND audience=? AND expires=? AND jti=?', [
            $client_id,
            $subject,
            $audience,
            $expires,
            $jti
        ]);

        return $result?[
            'issuer' => $result['issuer'],
            'subject' => $result['subject'],
            'audience' => $result['audience'],
            'expires' => $result['expires'],
            'jti' => $result['jti'],
        ]:null;

        #TODO delete
        $stmt = $this->db->prepare($sql = sprintf('SELECT * FROM %s WHERE issuer=:client_id AND subject=:subject AND audience=:audience AND expires=:expires AND jti=:jti', $this->config['jti_table']));

        $stmt->execute(compact('client_id', 'subject', 'audience', 'expires', 'jti'));

        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return [
                'issuer' => $result['issuer'],
                'subject' => $result['subject'],
                'audience' => $result['audience'],
                'expires' => $result['expires'],
                'jti' => $result['jti'],
            ];
        }

        return null;
    }

    public function setJti($client_id, $subject, $audience, $expires, $jti) {
        return $this->execute( $this->config['jti_table'],'INSERT INTO %s (issuer, subject, audience, expires, jti) VALUES (?, ?, ?, ?, ?)',[
            $client_id,
            $audience,
            $expires,
            $jti
        ]);

        #TODO delete
        $stmt = $this->db->prepare(sprintf('INSERT INTO %s (issuer, subject, audience, expires, jti) VALUES (:client_id, :subject, :audience, :expires, :jti)', $this->config['jti_table']));

        return $stmt->execute(compact('client_id', 'subject', 'audience', 'expires', 'jti'));
    }

    /* PublicKeyInterface */
    public function getPublicKey($client_id = null) {
        $result = $this->select($this->config['public_key_table'],'SELECT public_key FROM %s WHERE client_id=? OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC',[
            $client_id
        ]);
        return $result?$result['public_key']:null;

        #TODO delete
        $stmt = $this->db->prepare($sql = sprintf('SELECT public_key FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));

        $stmt->execute(compact('client_id'));
        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['public_key'];
        }
    }

    public function getPrivateKey($client_id = null) {
        $result = $this->select($this->config['public_key_table'],'SELECT private_key FROM %s WHERE client_id=? OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC',[
            $client_id
        ]);
        return $result?$result['private_key']:null;

        #TODO delete

        $stmt = $this->db->prepare($sql = sprintf('SELECT private_key FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));

        $stmt->execute(compact('client_id'));
        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['private_key'];
        }
    }

    public function getEncryptionAlgorithm($client_id = null) {
        $result = $this->select($this->config['public_key_table'],'SELECT encryption_algorithm FROM %s WHERE client_id=? OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC',[
            $client_id
        ]);

        return $result?$result['encryption_algorithm']:'RS256';

        #TODO delete
        $stmt = $this->db->prepare($sql = sprintf('SELECT encryption_algorithm FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));

        $stmt->execute(compact('client_id'));
        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['encryption_algorithm'];
        }

        return 'RS256';
    }

    /**
     * DDL to create OAuth2 database and tables for PDO storage
     *
     * @see https://github.com/dsquier/oauth2-server-php-mysql
     */
    public function getBuildSql($dbName = 'oauth2_server_php') {
        $sql = "
        CREATE TABLE {$this->config['client_table']} (
          client_id             VARCHAR(80)   NOT NULL,
          client_secret         VARCHAR(80)   NOT NULL,
          redirect_uri          VARCHAR(2000),
          grant_types           VARCHAR(80),
          scope                 VARCHAR(4000),
          user_id               VARCHAR(80),
          PRIMARY KEY (client_id)
        );

        CREATE TABLE {$this->config['access_token_table']} (
          access_token         VARCHAR(40)    NOT NULL,
          client_id            VARCHAR(80)    NOT NULL,
          user_id              VARCHAR(80),
          expires              TIMESTAMP      NOT NULL,
          scope                VARCHAR(4000),
          PRIMARY KEY (access_token)
        );

        CREATE TABLE {$this->config['code_table']} (
          authorization_code  VARCHAR(40)    NOT NULL,
          client_id           VARCHAR(80)    NOT NULL,
          user_id             VARCHAR(80),
          redirect_uri        VARCHAR(2000),
          expires             TIMESTAMP      NOT NULL,
          scope               VARCHAR(4000),
          id_token            VARCHAR(1000),
          PRIMARY KEY (authorization_code)
        );

        CREATE TABLE {$this->config['refresh_token_table']} (
          refresh_token       VARCHAR(40)    NOT NULL,
          client_id           VARCHAR(80)    NOT NULL,
          user_id             VARCHAR(80),
          expires             TIMESTAMP      NOT NULL,
          scope               VARCHAR(4000),
          PRIMARY KEY (refresh_token)
        );

        CREATE TABLE {$this->config['user_table']} (
          username            VARCHAR(80),
          password            VARCHAR(80),
          first_name          VARCHAR(80),
          last_name           VARCHAR(80),
          email               VARCHAR(80),
          email_verified      BOOLEAN,
          scope               VARCHAR(4000)
        );

        CREATE TABLE {$this->config['scope_table']} (
          scope               VARCHAR(80)  NOT NULL,
          is_default          BOOLEAN,
          PRIMARY KEY (scope)
        );

        CREATE TABLE {$this->config['jwt_table']} (
          client_id           VARCHAR(80)   NOT NULL,
          subject             VARCHAR(80),
          public_key          VARCHAR(2000) NOT NULL
        );

        CREATE TABLE {$this->config['jti_table']} (
          issuer              VARCHAR(80)   NOT NULL,
          subject             VARCHAR(80),
          audiance            VARCHAR(80),
          expires             TIMESTAMP     NOT NULL,
          jti                 VARCHAR(2000) NOT NULL
        );

        CREATE TABLE {$this->config['public_key_table']} (
          client_id            VARCHAR(80),
          public_key           VARCHAR(2000),
          private_key          VARCHAR(2000),
          encryption_algorithm VARCHAR(100) DEFAULT 'RS256'
        )
";

        return $sql;
    }
}
