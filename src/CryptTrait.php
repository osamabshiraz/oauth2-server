<?php

namespace League\OAuth2\Server;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use Exception;
use LogicException;

trait CryptTrait
{
    /**
     * @var string|Key|null
     */
    protected $encryptionKey;

    /**
     * Encrypt data with encryptionKey.
     *
     * @param string $unencryptedData
     *
     * @throws LogicException
     *
     * @return string
     */
    protected function encrypt($unencryptedData)
    {
        try {
            if (!$this->encryptionKey) {
                $this->encryptionKey = Key::loadFromAsciiSafeString(config('app.encryption_key'));
            }

            if ($this->encryptionKey instanceof Key) {
                return Crypto::encrypt($unencryptedData, $this->encryptionKey);
            }

            if (is_string($this->encryptionKey)) {
                return Crypto::encryptWithPassword($unencryptedData, $this->encryptionKey);
            }

            throw new LogicException('Encryption key not set when attempting to encrypt');
        } catch (Exception $e) {
            throw new LogicException($e->getMessage(), 0, $e);
        }
    }

    /**
     * Decrypt data with encryptionKey.
     *
     * @param string $encryptedData
     *
     * @throws LogicException
     *
     * @return string
     */
    protected function decrypt($encryptedData)
    {
        try {
            if (!$this->encryptionKey) {
                $this->encryptionKey = Key::loadFromAsciiSafeString(config('app.encryption_key'));
            }

            if ($this->encryptionKey instanceof Key) {
                return Crypto::decrypt($encryptedData, $this->encryptionKey);
            }

            if (is_string($this->encryptionKey)) {
                return Crypto::decryptWithPassword($encryptedData, $this->encryptionKey);
            }

            throw new LogicException('Encryption key not set when attempting to decrypt');
        } catch (Exception $e) {
            throw new LogicException($e->getMessage(), 0, $e);
        }
    }

    /**
     * Set the encryption key manually (optional if you want to override lazy load).
     *
     * @param string|Key|null $key
     */
 public function setEncryptionKey($key = null)
{


    $asciiSafeKey = config('app.encryption_key');
    $this->encryptionKey = Key::loadFromAsciiSafeString($asciiSafeKey);
}
}
