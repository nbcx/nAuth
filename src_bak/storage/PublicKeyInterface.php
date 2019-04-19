<?php
namespace nbcx\oauth\server\storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should get public/private key information
 */
interface PublicKeyInterface {

    public function getPublicKey($client_id = null);
    public function getPrivateKey($client_id = null);
    public function getEncryptionAlgorithm($client_id = null);
}
