<?php

class JWT
{
    protected const ALGORITHM = 'HS256';
    protected const TYPE = 'JWT';

    /**
     * Summary of __construct
    * @param string $secret
    * @param string $issuer
    * @param int $ttl
    */
    function __construct(
        protected string $secret = '',
        protected string $issuer = '',
        protected int $ttl = 3600
    ) { }

    /**
     * Summary of generate
     * @param array $payload
     * @param array $headers
     * @return string
     */
    public function generate(
        array $payload,
        array $headers = []
    ): string {
        $headers['alg'] = self::ALGORITHM;
        $headers['typ'] = self::TYPE;

        if (strlen($this->issuer) > 0) {
            $headers['iss'] = $this->issuer;
            $payload['iss'] = $this->issuer;
        }

        if (isset($payload['iat']) && is_string($payload['iat'])) {
            $payload['iat'] = strtotime($payload['iat']);
        } elseif (isset($payload['iat']) && is_bool($payload['iat']) && $payload['iat']) {
            $payload['iat'] = time();
        }

        if (isset($payload['exp']) && is_string($payload['exp'])) {
            $payload['exp'] = strtotime($payload['exp']);
        } elseif (isset($payload['exp']) && is_bool($payload['exp']) && $payload['exp']) {
            $payload['exp'] = time() + $this->ttl;
        }

        if (isset($payload['nbf']) && is_string($payload['nbf'])) {
            $payload['nbf'] = strtotime($payload['nbf']);
        }

        return implode('.', array_values($this->compile($headers, $payload)));
    }

    /**
     * Summary of extract
     * @param string $jwt
     * @return array
     */
    public function extract(
        string $jwt
    ): array {
        $tokenParts = explode('.', $jwt);
        $json_header = base64_decode($tokenParts[0]);
        $json_payload = base64_decode($tokenParts[1]);
        $signature = $tokenParts[2];

        $header = json_decode($json_header, true);
        $payload = json_decode($json_payload, true);

        return compact('header', 'payload', 'signature');
    }

    /**
     * Summary of validate
     * @param string $jwt
     * @return bool
     */
    public function validate(
        string $jwt
    ): bool {
        $extracted = $this->extract($jwt);
        $header = $extracted['header'] ?? [];
        $payload = $extracted['payload'] ?? [];
        $signature = $extracted['signature'] ?? '';

        if (strlen($this->issuer) > 0 && ($this->issuer !== $header['iss'] || $this->issuer !== $payload['iss'])) {
            return false;
        }

        if(isset($payload['exp']) && $payload['exp'] - time() < 0) {
            return false;
        }

        if(isset($payload['nbf']) && $payload['nbf'] - time() > 0) {
            return false;
        }

        return $signature === $this->compile($header, $payload)['signature'];
    }

    /**
     * Summary of compile
     * @param array $headerData
     * @param array $payloadData
     * @return array
     */
    protected function compile(
        array $headerData,
        array $payloadData,
    ): array {
        $header = $this->base64urlEncode(json_encode($headerData));
        $payload = $this->base64urlEncode(json_encode($payloadData));

        $signatureData = hash_hmac('SHA256', "$header.$payload", $this->secret, true);
        $signature = $this->base64urlEncode($signatureData);

        return compact('header', 'payload', 'signature');
    }

    /**
     * Summary of base64urlEncode
     * @param string $str
     * @return string
     */
    protected function base64urlEncode(
        string $str
    ): string {
        return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
    }
}