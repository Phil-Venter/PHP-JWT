<?php

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
        protected string $secret = '',
        protected string $issuer = '',
        protected int $ttl = 3_600
    ) { }

    public function generate(array $payload, array $headers = []): string
    {
        $headers[self::HEADER_ALGORITHM] = self::HEADER_ALGORITHM_VALUE;
        $headers[self::HEADER_TYPE] = self::HEADER_TYPE_VALUE;

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

        return implode('.', array_values($this->compile($headers, $payload)));
    }

    public function extract(string $jwt): array
    {
        $tokenParts = explode('.', $jwt);
        $jsonHeader = base64_decode($tokenParts[0]);
        $jsonPayload = base64_decode($tokenParts[1]);
        $signature = $tokenParts[2];

        $header = json_decode($jsonHeader, true);
        $payload = json_decode($jsonPayload, true);

        return [
            self::HEADER => $header,
            self::PAYLOAD => $payload,
            self::SIGNATURE => $signature,
        ];
    }

    public function validate(string $jwt): bool
    {
        $extracted = $this->extract($jwt);
        $header = $extracted[self::HEADER] ?? [];
        $payload = $extracted[self::PAYLOAD] ?? [];
        $signature = $extracted[self::SIGNATURE] ?? '';

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

        return $signature === $this->compile($header, $payload)[self::SIGNATURE];
    }

    protected function compile(array $headerData, array $payloadData): array
    {
        $header = StringHelper::base64UrlEncode(json_encode($headerData));
        $payload = StringHelper::base64UrlEncode(json_encode($payloadData));

        $signatureData = hash_hmac(self::HASH_ALGORITHM, "$header.$payload", $this->secret, true);
        $signature = StringHelper::base64UrlEncode($signatureData);

        return [
            self::HEADER => $header,
            self::PAYLOAD => $payload,
            self::SIGNATURE => $signature,
        ];
    }
}

class StringHelper
{
    public static function base64UrlEncode(string $str): string
    {
        return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
    }
}