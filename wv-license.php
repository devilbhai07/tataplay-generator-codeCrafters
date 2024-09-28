<?php

$id = $_REQUEST['id'];

//header("Content-Type: application/json");
function download_video($videoUrl, $userAgent, $cookie) {
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $videoUrl);
    curl_setopt($ch, CURLOPT_COOKIE, $cookie);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    
    $videoContent = curl_exec($ch);

    if (curl_errno($ch)) {
        // Handle error
        $error_msg = curl_error($ch);
        curl_close($ch);
        throw new Exception('cURL error: ' . $error_msg);
    }

    curl_close($ch);

    return $videoContent;
}

function capture_cookies($url) {
    //echo $url;
    $cookie_file = tempnam(sys_get_temp_dir(), 'cookie');
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_COOKIEJAR, $cookie_file);
    curl_setopt($ch, CURLOPT_COOKIEFILE, $cookie_file);

    $response = curl_exec($ch);
     //echo $response;
    if ($response === false) {
        die('cURL error: ' . curl_error($ch));
    }

    curl_close($ch);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $header = substr($response, 0, $header_size);
    $body = substr($response, $header_size);

    preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $header, $matches);
    $cookies = [];
    foreach ($matches[1] as $cookie) {
        parse_str($cookie, $cookie_array);
        $cookies = array_merge($cookies, $cookie_array);
    }

    return [
        'cookies' => $cookies,
        'body' => $body,
        'cookie_file' => $cookie_file
    ];
}

function decrypt_source_url($encrypted_url) {
    $SECRET_KEY = "aesEncryptionKey";
    $cipher = "AES-128-ECB";
    $encrypted_url = substr($encrypted_url, 0, -3);

    $decoded_data = base64_decode($encrypted_url);
    if ($decoded_data === false) {
        return "Error: Base64 decoding failed.";
    }

    $decrypted = openssl_decrypt($decoded_data, $cipher, $SECRET_KEY, OPENSSL_RAW_DATA);
    if ($decrypted === false) {
        return "Error: Decryption failed.";
    }

    $padding_length = ord(substr($decrypted, -1));
    if ($padding_length >= 1 && $padding_length <= 16) {
        $decrypted = substr($decrypted, 0, -$padding_length);
    } else {
        $decrypted = rtrim($decrypted);
    }

    return $decrypted;
}

function secure_values($action, $data) {
    $protec = "";
    $method = 'AES-128-CBC';
    $ky = 'joincodecrafters';
    $iv = substr(sha1($ky.'coolapps'."24662b4f995b7b3d348211c94fdaa080"), 0, 16);
    
    if ($action == "encrypt") {
        $encrypted = openssl_encrypt($data, $method, $ky, OPENSSL_RAW_DATA, $iv);
        if (!empty($encrypted)) {
            $protec = bin2hex($encrypted);
        }
    } else {
        $decrypted = openssl_decrypt(hex2bin($data), $method, $ky, OPENSSL_RAW_DATA, $iv);
        if (!empty($decrypted)) {
            $protec = $decrypted;
        }
    }
    return $protec;
}


function findMatchingEntitlement($entitlements, $epids) {
    foreach ($entitlements as $entitlement) {
        if (in_array($entitlement["pkgId"], $epids)) {
            return $entitlement["pkgId"];
        }
    }
    return null;
}


$getUData = @file_get_contents('secure/_sessionData');
$decUData = secure_values('decrypt', $getUData);
$TATA_DATA = @json_decode($decUData, true);
$TPAUTH = array(
    'access_token' => $TATA_DATA['data']['accessToken'],
    'refresh_token' => $TATA_DATA['data']['refreshToken'],
    'subscriberID' => $TATA_DATA['data']['userDetails']['sid'],
    'subscriberRMN' => $TATA_DATA['data']['userDetails']['rmn'],
    'subscriberNAME' => $TATA_DATA['data']['userDetails']['sName'],
    'profileID' => $TATA_DATA['data']['userProfile']['id'],
    'deviceName' => $TATA_DATA['data']['deviceDetails']['deviceName'],
    'entitlements' => $TATA_DATA['data']['userDetails']['entitlements']
);

$chnDetailsAPI = 'https://tm.tapi.videoready.tv/digital-feed-services/api/partner/cdn/player/details/LIVE/' . $id;
$chnDlHeads = array(
    'Accept-Language: en-US,en;q=0.9',
    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'device_details: {"pl":"web","os":"WINDOWS","lo":"en-us","app":"1.41.19","dn":"PC","bv":126,"bn":"CHROME","device_id":"24662b4f995b7b3d348211c94fdaa080","device_type":"WEB","device_platform":"PC","device_category":"open","manufacturer":"WINDOWS_CHROME_126","model":"PC","sname":"'.$TPAUTH['subscriberNAME'].'"}',
    'Referer: https://watch.tataplay.com/',
    'Origin: https://watch.tataplay.com',
    'Authorization: bearer '.$TPAUTH['access_token'],
    'profileId: '.$TPAUTH['profileID'],
    'platform: web',
    'Rule: DRPVR',
    'locale: ENG',
    'kp: false'
);

$process = curl_init($chnDetailsAPI);
curl_setopt($process, CURLOPT_CUSTOMREQUEST, "GET");
curl_setopt($process, CURLOPT_HTTPHEADER, $chnDlHeads);
curl_setopt($process, CURLOPT_HEADER, 0);
curl_setopt($process, CURLOPT_TIMEOUT, 10);
curl_setopt($process, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($process, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($process, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
$chnOut = curl_exec($process);
if ($chnOut === false) {
    die('cURL error: ' . curl_error($process));
}
curl_close($process);

//echo $chnOut;
$vUData = @json_decode($chnOut, true);
$widevine = decrypt_source_url($vUData['data']['dashWidewineLicenseUrl']);
$mpd = decrypt_source_url($vUData['data']['dashWidewinePlayUrl']);
$sub_epid = $vUData['data']['entitlements'];
//var_dump($vUData);
//var_dump($widevine);
//var_dump($mpd);
//var_dump($sub_epid);
//echo $mpd;

$epid = findMatchingEntitlement($TPAUTH['entitlements'], $sub_epid);
$jwtpay = "{\"action\":\"stream\",\"epids\":[{\"epid\":\"Subscription\",\"bid\":\"$epid\"}]}";

$sherlocation = 'https://tm.tapi.videoready.tv/auth-service/v2/oauth/token-service/'.$id.'/LIVE/token';
$sherheads = array(
    'Accept-Language: en-US,en;q=0.9',
    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'content-type: application/json',
    'device_details: {"pl":"web","os":"WINDOWS","lo":"en-us","app":"1.41.19","dn":"PC","bv":126,"bn":"CHROME","device_id":"24662b4f995b7b3d348211c94fdaa080","device_type":"WEB","device_platform":"PC","device_category":"open","manufacturer":"WINDOWS_CHROME_126","model":"PC","sname":"'.$TPAUTH['subscriberNAME'].'"}',
    'kp: false',
    'locale: ENG',
    'Rule: DRPVR',
    'platform: web',
    'profileId: '.$TPAUTH['profileID'],
    'Referer: https://watch.tataplay.com/',
    'x-device-id: '."24662b4f995b7b3d348211c94fdaa080",
    'x-device-platform: PC',
    'x-device-type: WEB',
    'x-subscriber-id: '.$TPAUTH['subscriberID'],
    'x-subscriber-name: '.$TPAUTH['subscriberNAME'],
    'Authorization: bearer '.$TPAUTH['access_token'],
    'Origin: https://watch.tataplay.com'
);

$sherposts = $jwtpay;
$process = curl_init($sherlocation);
curl_setopt($process, CURLOPT_POST, 1);
curl_setopt($process, CURLOPT_POSTFIELDS, $sherposts);
curl_setopt($process, CURLOPT_HTTPHEADER, $sherheads);
curl_setopt($process, CURLOPT_HEADER, 0);
curl_setopt($process, CURLOPT_ENCODING, '');
curl_setopt($process, CURLOPT_TIMEOUT, 10);
curl_setopt($process, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($process, CURLOPT_FOLLOWLOCATION, 1);
$vrswvx = curl_exec($process);
curl_close($process);
$mksaz= @json_decode($vrswvx, true);        
$ls_session = 'ls_session='.$mksaz['data']['token'];
$licurl = $widevine.'&'.$ls_session;
//http_response_code(307);
header("Location: $licurl" , true , 307);
exit();
?>
