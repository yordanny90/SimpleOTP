<?php

/**
 * Repositorio {@link https://github.com/yordanny90/SimpleOTP}
 *
 */
class SimpleOTP{
    private const ALPHABET='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    private $binSecret;
    private $period=30;

    private function __construct(string $binSecret){
        $this->binSecret=$binSecret;
    }

    /**
     * @param int $period 15, 30, 60
     */
    public function setTOTP_period(int $period){
        if(in_array($period, [15, 30, 60])) $this->period=$period;
    }

    /**
     * @return int
     */
    public function getTOTP_period(){
        return $this->period;
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

    public function createLinkTOTP(string $issuer='', string $label=''){
        return 'otpauth://totp/'.urlencode($issuer).':'.urlencode($label).'?issuer='.urlencode($issuer).'&secret='.self::bin_base32($this->binSecret).'&algorithm=SHA1&digits=6&period='.$this->period;
    }

    /**
     * @param int|null $time Tiempo UNIX para generar el counter. Si es NULL, se usa el tiempo actual del sistema
     * @return int
     */
    public function timeToCounter(?int $time=null){
        return intval(($time??time())/$this->period);
    }

    /**
     * @param int $counter Counter que se convertirá en el time correspondiente
     * @return int
     */
    public function counterToTime(int $counter){
        return $counter*$this->period;
    }

    public function TOTP(){
        return self::genOTP($this->binSecret, $this->timeToCounter());
    }

    /**
     * @param string $code Código a verificar
     * @param int $time_diff Diferencia máxima permitida en segundos
     * @param int|null $time_used Devuelve el time correspondiente al código verificado
     * @return bool
     */
    public function checkTOTP(string $code, int $time_diff=0, ?int &$time_used=null){
        $t=time();
        $time_diff=abs($time_diff);
        $counterA=$this->timeToCounter($t-$time_diff);
        $counterB=$this->timeToCounter($t+$time_diff);
        $success=self::checkHOTP($counterA, $code, $counterB, $counter_found);
        $time_used=$success?$this->counterToTime($counter_found):null;
        return $success;
    }

    public function HOTP(int $counter){
        return self::genOTP($this->binSecret, $counter);
    }

    /**
     * @param int $counter
     * @param string $code Código a verificar
     * @param int|null $max_counter Opcional. Counter máximo permitido de la búsqueda
     * @param int|null $counter_found Devuelve el counter que coincide con el código
     * @return bool
     */
    public function checkHOTP(int $counter, string $code, ?int $max_counter=null, ?int &$counter_found=null){
        $counter_found=null;
        $c=$counter;
        do{
            $found=($code===self::genOTP($this->binSecret, $c));
        }while(!$found && $max_counter!==null && $c<$max_counter && ++$c);
        if(!$found) return false;
        $counter_found=$c;
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
