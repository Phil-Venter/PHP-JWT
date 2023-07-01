<?php declare(strict_types=1);

class JWT
{
    public const HEADER = 'header';
    public const PAYLOAD = 'payload';
    public const SIGNATURE = 'signature';

    protected const HASH_ALGORITHM = 'SHA256';

    protected const HEADER_ALGORITHM = 'alg';
    protected const HEADER_ALGORITHM_VALUE = 'HS256';
    protected const HEADER_TYPE = 'typ';
    protected const HEADER_TYPE_VALUE = 'JWT';

    protected const PAYLOAD_ISSUER = 'iss';
    protected const PAYLOAD_ISSUED_AT = 'iat';
    protected const PAYLOAD_EXPIRY = 'exp';
    protected const PAYLOAD_NOT_BEFORE = 'nbf';

    public function __construct(
        protected string $secret,
        protected string $issuer = '',
        protected int $ttl = 3_600
    ) { }

    public function encode(array $payload, array $header = []): string
    {
        $header[self::HEADER_ALGORITHM] = self::HEADER_ALGORITHM_VALUE;
        $header[self::HEADER_TYPE] = self::HEADER_TYPE_VALUE;

        if (!empty(trim($this->issuer))) {
            $payload[self::PAYLOAD_ISSUER] = $this->issuer;
        }

        if (is_string($payload[self::PAYLOAD_ISSUED_AT] ?? null)) {
            $payload[self::PAYLOAD_ISSUED_AT] = strtotime($payload[self::PAYLOAD_ISSUED_AT]);
        } elseif (is_bool($payload[self::PAYLOAD_ISSUED_AT] ?? null) && $payload[self::PAYLOAD_ISSUED_AT]) {
            $payload[self::PAYLOAD_ISSUED_AT] = time();
        }

        if (is_string($payload[self::PAYLOAD_EXPIRY] ?? null)) {
            $payload[self::PAYLOAD_EXPIRY] = strtotime($payload[self::PAYLOAD_EXPIRY]);
        } elseif (is_bool($payload[self::PAYLOAD_EXPIRY] ?? null) && $payload[self::PAYLOAD_EXPIRY]) {
            $payload[self::PAYLOAD_EXPIRY] = time() + $this->ttl;
        }

        if (is_string($payload[self::PAYLOAD_NOT_BEFORE] ?? null)) {
            $payload[self::PAYLOAD_NOT_BEFORE] = strtotime($payload[self::PAYLOAD_NOT_BEFORE]);
        }

        return implode('.', array_values($this->construct($header, $payload)));
    }

    /**
     * Encode header, payload and create signature
     *
     * @param array $headerData
     * @param array $payloadData
     *
     * @return array
     */
    protected function construct(array $headerData, array $payloadData): array
    {
        $header = StringHelper::base64UrlEncode(json_encode($headerData));
        $payload = StringHelper::base64UrlEncode(json_encode($payloadData));

        $signatureData = hash_hmac(self::HASH_ALGORITHM, "{$header}.{$payload}", $this->secret, true);
        $signature = StringHelper::base64UrlEncode($signatureData);

        return [
            self::HEADER => $header,
            self::PAYLOAD => $payload,
            self::SIGNATURE => $signature,
        ];
    }

    /**
     * Decodes The JWT into the header and payload if it is invalid this will throw an error
     *
     * @param string $jwt
     *
     * @throws InvalidJWTException
     *
     * @return array
     */
    public function decode(string $jwt): array
    {
        $extracted = $this->destruct($jwt);

        $header = $extracted[self::HEADER] ?? [];
        $payload = $extracted[self::PAYLOAD] ?? [];
        $signature = $extracted[self::SIGNATURE] ?? '';

        if (!$this->compare($header, $payload, $signature)) {
            throw new InvalidJWTException();
        }

        return [
            self::HEADER => $header,
            self::PAYLOAD => $payload,
        ];
    }

    /**
     * Converts the JWT string into decoded parts
     *
     * @param string $jwt
     *
     * @return array
     */
    protected function destruct(string $jwt)
    {
        $tokenParts = explode('.', $jwt);

        $header = json_decode(base64_decode($tokenParts[0]), true);
        $payload = json_decode(base64_decode($tokenParts[1]), true);
        $signature = $tokenParts[2];

        return [
            self::HEADER => $header,
            self::PAYLOAD => $payload,
            self::SIGNATURE => $signature,
        ];
    }

    /**
     * Checks if the JWT token is valid by calling the internal compare function
     *
     * @param string $jwt
     *
     * @return bool
     */
    public function validate(string $jwt): bool
    {
        $extracted = $this->destruct($jwt);

        $header = $extracted[self::HEADER] ?? [];
        $payload = $extracted[self::PAYLOAD] ?? [];
        $signature = $extracted[self::SIGNATURE] ?? '';

        return $this->compare($header, $payload, $signature);
    }

    /**
     * Rebuilds the JWT based on the parts and validates that against the passed signature
     *
     * @param array $header
     * @param array $payload
     * @param string $signature
     *
     * @return bool
     */
    protected function compare(array $header, array $payload, string $signature): bool
    {
        $isIssuerSetInPayload = !isset($payload[self::PAYLOAD_ISSUER])
            || $this->issuer !== $payload[self::PAYLOAD_ISSUER];
        if (!empty(trim($this->issuer)) && $isIssuerSetInPayload) {
            return false;
        }

        if($payload[self::PAYLOAD_ISSUED_AT] ?? 0 - time() > 0) {
            return false;
        }

        if($payload[self::PAYLOAD_EXPIRY] ?? PHP_INT_MAX - time() < 0) {
            return false;
        }

        if($payload[self::PAYLOAD_NOT_BEFORE] ?? 0 - time() > 0) {
            return false;
        }

        return $signature === $this->construct($header, $payload)[self::SIGNATURE];
    }
}
