<?php

class JWT {
	function __construct(
        protected string $secret = '',
        protected string $issuer = '',
        protected int $ttl = 3600
    ) { }

    public function generate(
        array $payload,
        array $headers = []
    ) {
        $headers['alg'] = 'HS256';
		$headers['typ'] = 'JWT';

        if (strlen($this->issuer) > 0) {
            $headers['iss'] = $this->issuer;
			$payload['iss'] = $this->issuer;
        }

        if (is_string($payload['iat'])) {
            $payload['iat'] = strtotime($payload['iat']);
        } elseif (is_bool($payload['iat']) && $payload['iat']) {
            $payload['iat'] = time();
        }

        if (is_string($payload['exp'])) {
            $payload['exp'] = strtotime($payload['exp']);
        } elseif (is_bool($payload['exp']) && $payload['exp']) {
            $payload['exp'] = time() + $this->ttl;
        }

        if (is_string($payload['nbf'])) {
            $payload['nbf'] = strtotime($payload['nbf']);
        }

        return implode('.', array_values($this->compile($headers, $payload)));
    }

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

    public function validate(
        string $jwt
    ): bool {
        list($headers, $payload, $signature) = $this->extract($jwt);

        if (strlen($this->issuer) > 0 && !($this->issuer === $headers['iss'] === $payload['iss'])) {
            return false;
        }

        if(isset($payload['exp']) && $payload['exp'] - time() < 0) {
			return false;
		}

        if(isset($payload['nbf']) && $payload['nbf'] - time() > 0) {
			return false;
		}

        return $signature === $this->compile($headers, $payload)['signature'];
    }

    protected function base64urlEncode(
        string $str
    ): string {
		return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
	}
}