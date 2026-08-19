<?php

declare(strict_types=1);

// The archived dependencies predate PHP 8.5. Keep warnings/errors visible while
// excluding deprecation noise so the verifier has a stable machine-readable output.
error_reporting(E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED);

use Jubo\JuLiao\IM\Wx\Proto\DeviceAuthReqMessage;
use Jubo\JuLiao\IM\Wx\Proto\FriendTalkNoticeMessage;
use Jubo\JuLiao\IM\Wx\Proto\HeartBeatMessage;
use Jubo\JuLiao\IM\Wx\Proto\TalkToFriendTaskMessage;
use Jubo\JuLiao\IM\Wx\Proto\TransportMessage;

const EXPECTED_FIXTURE_COUNT = 15;
const PROTOBUF_TYPE_PREFIX = 'type.googleapis.com/Jubo.JuLiao.IM.Wx.Proto.';
const UNKNOWN_FIELD_127 = "\xf8\x07\x01";

function requireReadableFile(string $path): void
{
    if (!is_file($path) || !is_readable($path)) {
        throw new RuntimeException('required compatibility input is unavailable');
    }
    require_once $path;
}

function decodeFrame(string $frameHex): string
{
    if ($frameHex === '' || !ctype_xdigit($frameHex) || strlen($frameHex) % 2 !== 0) {
        throw new RuntimeException('fixture frame_hex is not valid hexadecimal');
    }
    $frame = hex2bin($frameHex);
    if ($frame === false || strlen($frame) < 4) {
        throw new RuntimeException('fixture frame is shorter than its header');
    }
    $header = unpack('Nlength', substr($frame, 0, 4));
    if (!is_array($header) || $header['length'] !== strlen($frame) - 4) {
        throw new RuntimeException('fixture frame length prefix does not match its body');
    }
    return substr($frame, 4);
}

function newInnerMessage(string $messageType): object
{
    return match ($messageType) {
        'DeviceAuthReqMessage' => new DeviceAuthReqMessage(),
        'HeartBeatMessage' => new HeartBeatMessage(),
        'FriendTalkNoticeMessage' => new FriendTalkNoticeMessage(),
        'TalkToFriendTaskMessage' => new TalkToFriendTaskMessage(),
        default => throw new RuntimeException('fixture message_type is not approved'),
    };
}

function expectedGetters(string $messageType): array
{
    return match ($messageType) {
        'TransportMessage' => [
            'Id' => 'getId',
            'AccessToken' => 'getAccessToken',
            'MsgType' => 'getMsgType',
            'Content' => 'getContent',
            'RefMessageId' => 'getRefMessageId',
        ],
        'DeviceAuthReqMessage' => [
            'AuthType' => 'getAuthType',
            'Credential' => 'getCredential',
        ],
        'HeartBeatMessage' => [
            'Imei' => 'getImei',
            'WeChatId' => 'getWeChatId',
        ],
        'FriendTalkNoticeMessage' => [
            'WeChatId' => 'getWeChatId',
            'FriendId' => 'getFriendId',
            'ContentType' => 'getContentType',
            'Content' => 'getContent',
            'MsgId' => 'getMsgId',
            'MsgSvrId' => 'getMsgSvrId',
            'Ext' => 'getExt',
            'CreateTime' => 'getCreateTime',
            'NickName' => 'getNickName',
        ],
        'TalkToFriendTaskMessage' => [
            'WeChatId' => 'getWeChatId',
            'FriendId' => 'getFriendId',
            'ContentType' => 'getContentType',
            'Content' => 'getContent',
            'Remark' => 'getRemark',
            'MsgId' => 'getMsgId',
            'Immediate' => 'getImmediate',
        ],
        default => throw new RuntimeException('fixture message_type is not approved'),
    };
}

function normalizeSemanticValue(mixed $value): string
{
    return match (true) {
        $value === null => 'absent',
        is_bool($value) => $value ? 'true' : 'false',
        is_int($value), is_float($value), is_string($value) => (string) $value,
        default => 'present',
    };
}

function verifyExpectedFields(object $message, string $messageType, array $expected): void
{
    $getters = expectedGetters($messageType);
    $expectedKeys = array_keys($expected);
    $getterKeys = array_keys($getters);
    sort($expectedKeys);
    sort($getterKeys);
    if ($expectedKeys !== $getterKeys) {
        throw new RuntimeException('normal fixture semantic field coverage is incomplete');
    }
    foreach ($getters as $field => $getter) {
        if (normalizeSemanticValue($message->{$getter}()) !== (string) $expected[$field]) {
            throw new RuntimeException('legacy PHP decoded an unexpected semantic field');
        }
    }
}

function verifyFixture(array $fixture): void
{
    foreach (['case', 'message_type', 'msg_type', 'frame_hex', 'unknown_scope'] as $key) {
        if (!array_key_exists($key, $fixture)) {
            throw new RuntimeException('fixture is missing a required key');
        }
    }

    $body = decodeFrame((string) $fixture['frame_hex']);
    $outer = new TransportMessage();
    $outer->mergeFromString($body);
    if ($outer->serializeToString() !== $body) {
        throw new RuntimeException('legacy PHP changed the transport body during round trip');
    }
    if ($outer->getMsgType() !== (int) $fixture['msg_type']) {
        throw new RuntimeException('legacy PHP decoded an unexpected message type');
    }

    $messageType = (string) $fixture['message_type'];
    $unknownScope = (string) $fixture['unknown_scope'];
    if ($messageType === 'TransportMessage') {
        if (str_ends_with((string) $fixture['case'], '-normal')) {
            verifyExpectedFields($outer, $messageType, (array) ($fixture['expected'] ?? []));
        }
        if ($unknownScope === 'outer' && !str_ends_with($body, UNKNOWN_FIELD_127)) {
            throw new RuntimeException('transport fixture is missing unknown field 127');
        }
        return;
    }

    $content = $outer->getContent();
    if ($content === null) {
        throw new RuntimeException('transport fixture is missing Any content');
    }
    if ($content->getTypeUrl() !== PROTOBUF_TYPE_PREFIX . $messageType) {
        throw new RuntimeException('transport fixture has an unexpected Any type URL');
    }

    $innerBody = $content->getValue();
    $inner = newInnerMessage($messageType);
    $inner->mergeFromString($innerBody);
    if ($inner->serializeToString() !== $innerBody) {
        throw new RuntimeException('legacy PHP changed the inner body during round trip');
    }
    if ($unknownScope === 'inner' && !str_ends_with($innerBody, UNKNOWN_FIELD_127)) {
        throw new RuntimeException('inner fixture is missing unknown field 127');
    }
    if (str_ends_with((string) $fixture['case'], '-normal')) {
        verifyExpectedFields($inner, $messageType, (array) ($fixture['expected'] ?? []));
    }
}

try {
    $legacyRoot = getenv('LEGACY_SOURCE_ROOT');
    if ($legacyRoot === false || $legacyRoot === '') {
        throw new RuntimeException('LEGACY_SOURCE_ROOT is not set');
    }
    if ($argc !== 2) {
        throw new RuntimeException('fixture manifest argument is required');
    }

    requireReadableFile($legacyRoot . '/vendor/autoload.php');
    foreach ([
        '/extend/lib/protobuf/GPBMetadata/TransportMessage.php',
        '/extend/lib/protobuf/GPBMetadata/DeviceAuthReq.php',
        '/extend/lib/protobuf/GPBMetadata/HeartBeat.php',
        '/extend/lib/protobuf/GPBMetadata/FriendTalkNotice.php',
        '/extend/lib/protobuf/GPBMetadata/TalkToFriendTask.php',
        '/extend/lib/protobuf/Jubo/JuLiao/IM/Wx/Proto/TransportMessage.php',
        '/extend/lib/protobuf/Jubo/JuLiao/IM/Wx/Proto/DeviceAuthReqMessage.php',
        '/extend/lib/protobuf/Jubo/JuLiao/IM/Wx/Proto/HeartBeatMessage.php',
        '/extend/lib/protobuf/Jubo/JuLiao/IM/Wx/Proto/FriendTalkNoticeMessage.php',
        '/extend/lib/protobuf/Jubo/JuLiao/IM/Wx/Proto/TalkToFriendTaskMessage.php',
    ] as $relativePath) {
        requireReadableFile($legacyRoot . $relativePath);
    }

    $manifest = json_decode((string) file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($manifest) || count($manifest) !== EXPECTED_FIXTURE_COUNT) {
        throw new RuntimeException('fixture manifest count is invalid');
    }
    foreach ($manifest as $fixture) {
        if (!is_array($fixture)) {
            throw new RuntimeException('fixture entry is not an object');
        }
        verifyFixture($fixture);
    }

    fwrite(STDOUT, 'legacy-php-fixtures=' . count($manifest) . PHP_EOL);
} catch (Throwable $error) {
    fwrite(STDERR, 'legacy-php-verification-failed: ' . $error->getMessage() . PHP_EOL);
    exit(1);
}
