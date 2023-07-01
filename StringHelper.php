<?php declare(strict_types=1);

class StringHelper
{
    public static function base64UrlEncode(string $str): string
    {
        return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
    }
}