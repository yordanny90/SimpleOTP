<?php

/**
 * Repositorio {@link https://github.com/yordanny90/SimpleOTP}
 *
 */
class SimpleOTP{
    private const ALPHABET='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    private $binSecret;

    private function __construct(string $binSecret){
        $this->binSecret=$binSecret;
    }

    public static function fromBase32(string $base32){
        $binSecret=self::base32_bin($base32);
        return new self($binSecret);
    }

    public static function fromBin(string $bin){
        return new self($bin);
    }

    public static function createSecretBase32(int $length=16){
        $length=max($length, 16);
        $val=self::bin_base32(self::createSecretBin(ceil($length*5/8)));
        if(strlen($val)>$length){
            $val=substr($val, 0, $length);
        }
        return $val;
    }

    public static function createSecretBin(int $length=10){
        $val=openssl_random_pseudo_bytes(max($length, 10));
        return $val;
    }

    public static function createLink(string $base32, string $issuer='', string $label=''){
        return 'otpauth://totp/'.urlencode($issuer).':'.urlencode($label).'?issuer='.urlencode($issuer).'&secret='.$base32.'&algorithm=SHA1&digits=6&period=30';
    }

    /**
     * @return int
     */
    public function getHOTPCounterForTOTP(){
        $time=time();
        // Calcula el contador basado en el tiempo actual y el intervalo (timeStep)
        $counter=intval($time/30);
        return $counter;
    }

    public function TOTP(){
        return self::genOTP($this->binSecret, $this->getHOTPCounterForTOTP());
    }

    /**
     * @param int $max_diff Max: 50. Diferencia máxima permitida para el último código de la secuencia
     * @param int|null $diff Devuelve la diferencia del último código de la secuencia, entre -50 y 50
     * @param string ...$otp_seq Secuencia de códigos consecutivos
     * @return bool
     */
    public function checkTOTP(int $max_diff, ?int &$diff=null, string ...$otp_seq){
        return self::checkHOTP($this->getHOTPCounterForTOTP(), $max_diff, $diff, ...$otp_seq);
    }

    public function HOTP(int $counter){
        return self::genOTP($this->binSecret, $counter);
    }

    /**
     * @param int $counter
     * @param int $max_diff Max: 50. Diferencia máxima permitida para el último código de la secuencia
     * @param int|null $diff Devuelve la diferencia del último código de la secuencia, entre -50 y 50
     * @param string ...$otp_seq Secuencia de códigos consecutivos
     * @return bool
     */
    public function checkHOTP(int $counter, int $max_diff=0, ?int &$diff=null, string ...$otp_seq){
        $diff=0;
        if(count($otp_seq)==0) return false;
        $otp=array_pop($otp_seq);
        $found=false;
        if($otp===self::genOTP($this->binSecret, $counter)){
            $found=true;
        }
        $max_diff=min($max_diff, 50);
        if(!$found && $max_diff>0) while(++$diff<=$max_diff && $counter+$diff>0){
            if($otp===self::genOTP($this->binSecret, $counter+$diff)){
                $found=true;
                $counter+=$diff;
                break;
            }
            if($otp===self::genOTP($this->binSecret, $counter-$diff)){
                $diff=-$diff;
                $found=true;
                $counter+=$diff;
                break;
            }
        }
        if(!$found){
            $diff=null;
            return false;
        }
        foreach(array_reverse($otp_seq) AS $otp){
            if($otp!==self::genOTP($this->binSecret, --$counter)) return false;
        }
        return true;
    }

    public static function bin_base32(string $bin){
        $buff='';
        $b32=implode('', array_map(function($v) use (&$buff){
            $buff.=str_pad(base_convert($v, 16, 2), 8, '0', STR_PAD_LEFT);
            $r='';
            while(strlen($buff)>=5){
                $v=bindec(substr($buff, 0, 5));
                $buff=substr($buff, 5);
                $r.=self::ALPHABET[$v] ?? '';
            }
            return $r;
        }, str_split(bin2hex($bin), 2)));
        if(strlen($buff)>=1){
            $v=bindec(str_pad($buff, 5, '0', STR_PAD_RIGHT));
            $b32.=self::ALPHABET[$v] ?? '';
        }
        return $b32;
    }

    public static function base32_bin(string $base32){
        $buff='';
        $bin=implode('', array_map(function($v) use (&$buff){
            $v=strpos(self::ALPHABET, $v);
            if($v!==false){
                $buff.=str_pad(decbin($v), 5, '0', STR_PAD_LEFT);
                if(strlen($buff)>=8){
                    list($v, $buff)=str_split($buff, 8);
                    $v=base_convert($v, 2, 10);
                    return chr($v);
                }
            }
            return '';
        }, str_split(strtoupper($base32))));
        return $bin;
    }

    private static function genOTP(string $binSecret, int $counter){
        $data=pack('N*', 0).pack('N*', $counter);
        $hash=hash_hmac('sha1', $data, $binSecret, true);
        $offset=ord($hash[19]) & 0xf;
        $code=(((ord($hash[$offset]) & 0x7f) << 24) | ((ord($hash[$offset+1]) & 0xff) << 16) | ((ord($hash[$offset+2]) & 0xff) << 8) | (ord($hash[$offset+3]) & 0xff))%1000000;
        return str_pad($code, 6, '0', STR_PAD_LEFT);
    }
}
