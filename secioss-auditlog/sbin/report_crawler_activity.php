<?php

require_once 'Log.php';
require_once 'IP2Location.php';

$logid = 'report_crawler_activity';
$log = &Log::singleton('syslog', LOG_LOCAL4, $logid);

$conf = parse_ini_file('/opt/secioss/etc/report_crawler_activity.conf');
if (empty($conf)) {
    $log->crit("Can't read configuration");
    exit(1);
}

define('LAST_EXECUTION_DATE', '/opt/secioss/var/lib/report/report.date');

function _elasticsearch_prepare($reqDetail, $beginTime, $endTime)
{
    global $log;
    // beginTime and endTime must on same jst date
    $begin_utc = gmdate('Y.m.d', strtotime($beginTime));
    $end_utc = gmdate('Y.m.d', strtotime($endTime));
    $request_uri = '/serviceaudit_'.$reqDetail['uri'].'*'.$begin_utc.',serviceaudit_'.$reqDetail['uri'].'*'.$end_utc.'/_search';
    $request_data = [];
    $request_data['query']['bool'] = $reqDetail['query_bool'];
    $request_data['query']['bool']['filter'][] = ['range' => ['@timestamp' => ['gte' => $beginTime, 'lte' => $endTime]]];
    $request_data['sort']['@timestamp']['order'] = 'asc';
    if (isset($reqDetail['aggs']) && !empty($reqDetail['aggs'])) {
        $request_data['aggs'] = $reqDetail['aggs'];
        $request_data['size'] = '0';
    } else {
        $request_data['size'] = '10000';
        $request_uri .= '?scroll=1m';
    }

    return [$request_uri, $request_data];
}

function _elasticsearch_search($request_uri, $request_data, $customrequest = 'POST')
{
    global $conf;
    global $log;
    $log->debug("_elasticsearch_search($request_uri, ".json_encode($request_data).')');

    foreach (explode(' ', $conf['elasticsearch']) as $url) {
        $headers = [
            'Content-Type: application/json',
        ];

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url.$request_uri);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $customrequest);
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($request_data));
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HEADER, true);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 60);

        $response = curl_exec($curl);
        $contents = substr($response, curl_getinfo($curl, CURLINFO_HEADER_SIZE));
        $result = json_decode($contents, true);

        curl_close($curl);
        return $result;
    }
}

function _elasticsearch_process($service, $activity, $source)
{
    global $log;

    $tenant = $source['tenant'];

    if (preg_match('/^\d{4}\-\d{2}\-\d{2}T\d{2}.*Z/', $source['@timestamp'])) {
        $dt = new DateTime($source['@timestamp']);
    } else {
        $dt = new DateTime($source['@timestamp'].'Z');
    }
    $dt->setTimezone(new DateTimeZone(date_default_timezone_get()));
    $date = $dt->format('Y-m-d');

    $ip = '';
    $domain = '';

    switch ($service) {
        case 'googleapps':
            $ip = isset($source['ipAddress']) ? $source['ipAddress'] : '';
            // Find domain on share event
            if ($activity == 'share') {
                foreach ($source['events'] as $event) {
                    if ($domain) {
                        break;
                    }
                    if ($event['name'] == 'change_user_access' || $event['name'] == 'change_acl_editors' || $event['name'] == 'shared_drive_membership_change') {
                        $valid_event = 0;
                        foreach ($event['parameters'] as $parameter) {
                            if (isset($parameter['name']) && $parameter['name'] == 'primary_event') {
                                if (isset($parameter['boolValue']) && $parameter['boolValue']) {
                                    $valid_event = 1;
                                    continue;
                                }
                            }
                            if ($valid_event) {
                                if (isset($parameter['name']) && $parameter['name'] == 'target_user') {
                                    if (isset($parameter['value']) && $parameter['value']) {
                                        $domain = strrpos($parameter['value'], '@') ? substr($parameter['value'], strrpos($parameter['value'], '@') + 1) : '';
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            break;
        case 'office365':
            $ip = isset($source['ClientIP']) ? $source['ClientIP'] : '';
            if ($activity == 'share') {
                // Find domain on share event
                if (isset($source['TargetUserOrGroupName']) && $source['TargetUserOrGroupName']) {
                    $domain = strrpos($source['TargetUserOrGroupName'], '@') ? substr($source['TargetUserOrGroupName'], strrpos($source['TargetUserOrGroupName'], '@') + 1) : '';
                }
            }
            break;
        case 'lineworks':
            $ip = isset($source['ip_address']) ? $source['ip_address'] : '';
            if ($activity == 'share') {
                // TODO Find domain on share event
                $domain = '';
            }
            break;
        case 'box':
            $ip = isset($source['ip_address']) ? $source['ip_address'] : '';
            if ($activity == 'share') {
                // Find domain on share event
                if (isset($source['accessible_by']['login']) && $source['accessible_by']['login']) {
                    $domain = strrpos($source['accessible_by']['login'], '@') ? substr($source['accessible_by']['login'], strrpos($source['accessible_by']['login'], '@') + 1) : '';
                }
            }
            break;
        case 'dropbox':
            $ip = isset($source['origin']['geo_location']['ip_address']) ? $source['origin']['geo_location']['ip_address'] : '';
            if ($activity == 'share') {
                // Find domain on share event
                if (isset($source['context']['email']) && $source['context']['email']) {
                    $domain = strrpos($source['context']['email'], '@') ? substr($source['context']['email'], strrpos($source['context']['email'], '@') + 1) : '';
                }
            }
            break;
        case 'aws':
            $ip = isset($source['sourceIPAddress']) ? $source['sourceIPAddress'] : '';
            if ($activity == 'share') {
                // Find domain on share event
                $domain = '';
            }
            break;
    }

    $processed = [
        'tenant' => $tenant,
        'date' => $date,
        'ip' => $ip,
        'domain' => $domain,
    ];

    return $processed;
}

function _get_activity_filter($service_id)
{
    if (preg_match('/^(.+)0\d+/', $service_id, $matches)) {
        $service = $matches[1];
    } else {
        $service = $service_id;
    }

    switch ($service) {
        case 'googleapps':
            $filter = [
                'view' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['should' => [['match' => ['events.name.keyword' => 'view']], ['match' => ['events.name.keyword' => 'preview']]], 'minimum_should_match' => 1],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ipAddress.keyword']]]]],
                ],
                'create' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['should' => [['match' => ['events.name.keyword' => 'create']], ['match' => ['events.name.keyword' => 'sheets_import']], ['match' => ['events.name.keyword' => 'add_to_folder']], ['match' => ['events.name.keyword' => 'untrash']]], 'minimum_should_match' => 1],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ipAddress.keyword']]]]],
                ],
                'update' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['should' => [['match' => ['events.name.keyword' => 'edit']], ['match' => ['events.name.keyword' => 'rename']], ['match' => ['events.name.keyword' => 'move']]], 'minimum_should_match' => 1],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ipAddress.keyword']]]]],
                ],
                'delete' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['should' => [['match' => ['events.name.keyword' => 'delete']], ['match' => ['events.name.keyword' => 'trash']], ['match' => ['events.name.keyword' => 'remove_from_folder']]], 'minimum_should_match' => 1],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ipAddress.keyword']]]]],
                ],
                'download' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['filter' => [['term' => ['events.name.keyword' => 'download']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ipAddress.keyword']]]]],
                ],
                'upload' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['filter' => [['term' => ['events.name.keyword' => 'upload']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ipAddress.keyword']]]]],
                ],
                'share' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['should' => [['match' => ['events.name.keyword' => 'change_user_access']], ['match' => ['events.name.keyword' => 'change_acl_editors']], ['match' => ['events.name.keyword' => 'shared_drive_membership_change']]], 'minimum_should_match' => 1],
                    //'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs'  => ['group_by_ip' => ['terms' => ['field' => 'ipAddress.keyword']]]]],
                ],
                'loginSuccess' => [
                    'uri' => "${service_id}_login_",
                    'query_bool' => ['filter' => [['term' => ['events.name.keyword' => 'login_success']], ['term' => ['events.type.keyword' => 'login']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ipAddress.keyword']]]]],
                ],
                'loginFail' => [
                    'uri' => "${service_id}_login_",
                    'query_bool' => ['filter' => [['term' => ['events.name.keyword' => 'login_failure']], ['term' => ['events.type.keyword' => 'login']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ipAddress.keyword']]]]],
                ],
                'usage' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ipAddress.keyword']]]]],
                ],
            ];
            break;
        case 'office365':
            $filter = [
                'view' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['UserAgent.keyword' => 'MSWAC']]],
                        'filter' => [['term' => ['Workload.keyword' => 'OneDrive']]],
                        'should' => [['match' => ['Operation.keyword' => 'PageViewed']], ['match' => ['Operation.keyword' => 'FilePreviewed']]],
                        'minimum_should_match' => 1,
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ClientIP.keyword']]]]],
                ],
                'create' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['UserAgent.keyword' => 'MSWAC']]],
                        'filter' => [['term' => ['Workload.keyword' => 'OneDrive']]],
                        'should' => [['match' => ['Operation.keyword' => 'FileCopied']], ['match' => ['Operation.keyword' => 'FileRestored']], ['match' => ['Operation.keyword' => 'FolderCopied']], ['match' => ['Operation.keyword' => 'FolderRestored']]],
                        'minimum_should_match' => 1,
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ClientIP.keyword']]]]],
                ],
                'update' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['UserAgent.keyword' => 'MSWAC']]],
                        'filter' => [['term' => ['Workload.keyword' => 'OneDrive']]],
                        'should' => [
                            ['match' => ['Operation.keyword' => 'FileModified']], ['match' => ['Operation.keyword' => 'FileModifiedExtended']], ['match' => ['Operation.keyword' => 'FileMoved']], ['match' => ['Operation.keyword' => 'FileRenamed']],
                            ['match' => ['Operation.keyword' => 'FolderModified']], ['match' => ['Operation.keyword' => 'FolderMoved']], ['match' => ['Operation.keyword' => 'FolderRenamed']],
                        ],
                        'minimum_should_match' => 1,
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ClientIP.keyword']]]]],
                ],
                'delete' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['UserAgent.keyword' => 'MSWAC']]],
                        'filter' => [['term' => ['Workload.keyword' => 'OneDrive']]],
                        'should' => [
                            ['match' => ['Operation.keyword' => 'FileDeleted']], ['match' => ['Operation.keyword' => 'FileDeletedFirstStageRecycleBin']], ['match' => ['Operation.keyword' => 'FileDeletedSecondStageRecycleBin']], ['match' => ['Operation.keyword' => 'FileVersionsAllMinorsRecycled']], ['match' => ['Operation.keyword' => 'FileVersionsAllRecycled']], ['match' => ['Operation.keyword' => 'FileVersionRecycled']],
                            ['match' => ['Operation.keyword' => 'FolderDeleted']], ['match' => ['Operation.keyword' => 'FolderDeletedFirstStageRecycleBin']], ['match' => ['Operation.keyword' => 'FolderDeletedSecondStageRecycleBin']],
                        ],
                        'minimum_should_match' => 1,
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ClientIP.keyword']]]]],
                ],
                'download' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['UserAgent.keyword' => 'MSWAC']]],
                        'filter' => [['term' => ['Workload.keyword' => 'OneDrive']]],
                        'should' => [['match' => ['Operation.keyword' => 'FileDownloaded']]],
                        'minimum_should_match' => 1,
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ClientIP.keyword']]]]],
                ],
                'upload' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['UserAgent.keyword' => 'MSWAC']]],
                        'filter' => [['term' => ['Workload.keyword' => 'OneDrive']]],
                        'should' => [['match' => ['Operation.keyword' => 'FileUploaded']]],
                        'minimum_should_match' => 1,
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ClientIP.keyword']]]]],
                ],
                'share' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['UserAgent.keyword' => 'MSWAC']]],
                        'filter' => [['term' => ['Workload.keyword' => 'OneDrive']]],
                        'should' => [['match' => ['Operation.keyword' => 'SharingSet']], ['match' => ['Operation.keyword' => 'AnonymousLinkCreated']], ['match' => ['Operation.keyword' => 'AnonymousLinkUpdated']], ['match' => ['Operation.keyword' => 'SharingInvitationCreated']], ['match' => ['Operation.keyword' => 'AccessInvitationUpdated']]],
                        'minimum_should_match' => 1,
                    ],
                    //'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs'  => ['group_by_ip' => ['terms' => ['field' => 'ClientIP.keyword']]]]],
                ],
                'loginSuccess' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['UserAgent.keyword' => 'MSWAC']]],
                        'filter' => [['term' => ['Operation.keyword' => 'UserLoggedIn']]],
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ClientIP.keyword']]]]],
                ],
                'loginFail' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['UserAgent.keyword' => 'MSWAC']]],
                        'filter' => [['term' => ['Operation.keyword' => 'UserLoginFailed']]],
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ClientIP.keyword']]]]],
                ],
                'usage' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['must_not' => [['match' => ['UserAgent.keyword' => 'MSWAC']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ClientIP.keyword']]]]],
                ],
            ];
            break;
        case 'lineworks':
            $filter = [
                'view' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['filter' => [['term' => ['task.keyword' => '']]]], // 閲覧：なし
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'create' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['should' => [['match' => ['task.keyword' => 'コピー']], ['match' => ['task.keyword' => '新規フォルダー']]], 'minimum_should_match' => 1],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'update' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['should' => [['match' => ['task.keyword' => 'ファイル修正']], ['match' => ['task.keyword' => '移動']], ['match' => ['task.keyword' => '名前変更']]], 'minimum_should_match' => 1],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'delete' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['filter' => [['term' => ['task.keyword' => '削除']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'download' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['filter' => [['term' => ['task.keyword' => 'ダウンロード']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'upload' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['filter' => [['term' => ['task.keyword' => 'アップロード']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'share' => [
                    'uri' => "${service_id}_drive_",
                    'query_bool' => ['filter' => [['term' => ['task.keyword' => '共有リンク作成']]]],
                    //'aggs'       => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs'  => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'loginSuccess' => [
                    'uri' => "${service_id}_auth_",
                    'query_bool' => ['filter' => [['term' => ['description.keyword' => 'ログインに成功しました。']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'loginFail' => [
                    'uri' => "${service_id}_auth_",
                    'query_bool' => ['filter' => [['wildcard' => ['description.keyword' => 'ログイン失敗*']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'usage' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
            ];
            break;
        case 'box':
            $filter = [
                'view' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['filter' => [['term' => ['event_type.keyword' => 'PREVIEW']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'create' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['should' => [['match' => ['event_type.keyword' => 'COPY']], ['match' => ['event_type.keyword' => 'UNDELETE']]], 'minimum_should_match' => 1],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'update' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['should' => [['match' => ['event_type.keyword' => 'EDIT']], ['match' => ['event_type.keyword' => 'MOVE']], ['match' => ['event_type.keyword' => 'RENAME']]], 'minimum_should_match' => 1],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'delete' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['filter' => [['term' => ['event_type.keyword' => 'DELETE']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'download' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['filter' => [['term' => ['event_type.keyword' => 'DOWNLOAD']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'upload' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['filter' => [['term' => ['event_type.keyword' => 'UPLOAD']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'share' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['filter' => [['term' => ['event_type.keyword' => 'COLLABORATION_INVITE']]]],
                    //'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs'  => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'loginSuccess' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['filter' => [['term' => ['event_type.keyword' => 'LOGIN']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'loginFail' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['filter' => [['term' => ['event_type.keyword' => 'FAILED_LOGIN*']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
                'usage' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'ip_address.keyword']]]]],
                ],
            ];
            break;
        case 'dropbox':
            $filter = [
                'view' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['filter' => [['term' => ['event_type.tag.keyword' => 'file_preview']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'origin.geo_location.ip_address.keyword']]]]],
                ],
                'create' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['should' => [['match' => ['event_type.tag.keyword' => 'file_copy']], ['match' => ['event_type.tag.keyword' => 'file_restore']], ['match' => ['event_type.tag.keyword' => 'create_foleder']]], 'minimum_should_match' => 1],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'origin.geo_location.ip_address.keyword']]]]],
                ],
                'update' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['should' => [['match' => ['event_type.tag.keyword' => 'file_edit']], ['match' => ['event_type.tag.keyword' => 'file_move']], ['match' => ['event_type.tag.keyword' => 'file_rename']], ['match' => ['event_type.tag.keyword' => 'file_revert']]], 'minimum_should_match' => 1],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'origin.geo_location.ip_address.keyword']]]]],
                ],
                'delete' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['should' => [['match' => ['event_type.tag.keyword' => 'file_delete']], ['match' => ['event_type.tag.keyword' => 'file_permanently_delete']]], 'minimum_should_match' => 1],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'origin.geo_location.ip_address.keyword']]]]],
                ],
                'download' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['filter' => [['term' => ['event_type.tag.keyword' => 'file_download']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'origin.geo_location.ip_address.keyword']]]]],
                ],
                'upload' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['filter' => [['term' => ['event_type.tag.keyword' => 'file_add']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'origin.geo_location.ip_address.keyword']]]]],
                ],
                'share' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['should' => [['match' => ['event_type.tag.keyword' => 'shared_content_add_member']], ['match' => ['event_type.tag.keyword' => 'shared_content_add_intitees']]], 'minimum_should_match' => 1],
                    //'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs'  => ['group_by_ip' => ['terms' => ['field' => 'origin.geo_location.ip_address.keyword']]]]],
                ],
                'loginSuccess' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['should' => [['match' => ['event_type.tag.keyword' => 'login_success']], ['match' => ['event_type.tag.keyword' => 'password_login_success']]], 'minimum_should_match' => 1],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'origin.geo_location.ip_address.keyword']]]]],
                ],
                'loginFail' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['should' => [['match' => ['event_type.tag.keyword' => 'login_fail']], ['match' => ['event_type.tag.keyword' => 'password_login_failed']], ['match' => ['event_type.tag.keyword' => 'sso_login_failed']]], 'minimum_should_match' => 1],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'origin.geo_location.ip_address.keyword']]]]],
                ],
                'usage' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'origin.geo_location.ip_address.keyword']]]]],
                ],
            ];
            break;
        case 'aws':
            $filter = [
                'view' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['userAgent.keyword' => '[AWSConfig]']]],
                        'filter' => [['term' => ['eventSource.keyword' => 's3.amazonaws.com']]],
                        'should' => [['match' => ['term' => ['eventName.keyword' => 'GetObject']]], ['term' => ['eventName.keyword' => 'GetObjects']]],
                        'minimum_should_match' => 1,
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'sourceIPAddress.keyword']]]]],
                ],
                'create' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['userAgent.keyword' => '[AWSConfig]']]],
                        'filter' => [['term' => ['eventSource.keyword' => 's3.amazonaws.com']]],
                        'should' => [['match' => ['term' => ['eventName.keyword' => 'CreateBucket']]], ['match' => ['eventName.keyword' => 'PostObject']], ['match' => ['eventName.keyword' => 'PutObject']], ['match' => ['eventName.keyword' => 'UploadPartCopy']]],
                        'minimum_should_match' => 1,
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'sourceIPAddress.keyword']]]]],
                ],
                //'update' => [
                //],
                'delete' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['userAgent.keyword' => '[AWSConfig]']]],
                        'filter' => [['term' => ['eventSource.keyword' => 's3.amazonaws.com']]],
                        'should' => [['match' => ['term' => ['eventName.keyword' => 'DeleteBucket']]], ['match' => ['eventName.keyword' => 'DeleteObject']], ['match' => ['eventName.keyword' => 'DeleteObjects']]],
                        'minimum_should_match' => 1,
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'sourceIPAddress.keyword']]]]],
                ],
                //'download' => [
                //],
                'upload' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['userAgent.keyword' => '[AWSConfig]']]],
                        'filter' => [['term' => ['eventSource.keyword' => 's3.amazonaws.com']]],
                        'should' => [['match' => ['term' => ['eventName.keyword' => 'CompleteMultipartUpload']]], ['match' => ['eventName.keyword' => 'CreateMultipartUpload']], ['match' => ['eventName.keyword' => 'UploadPart']]],
                        'minimum_should_match' => 1,
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'sourceIPAddress.keyword']]]]],
                ],
                //'share' => [
                //],
                'loginSuccess' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['userAgent.keyword' => '[AWSConfig]']]],
                        'filter' => [['term' => ['eventName.keyword' => 'ConsoleLogin']], ['term' => ['responseElements.ConsoleLogin.keyword' => 'Success']]],
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'sourceIPAddress.keyword']]]]],
                ],
                'loginFail' => [
                    'uri' => "${service_id}_",
                    'query_bool' => [
                        'must_not' => [['match' => ['userAgent.keyword' => '[AWSConfig]']]],
                        'filter' => [['term' => ['eventName.keyword' => 'ConsoleLogin']], ['term' => ['responseElements.ConsoleLogin.keyword' => 'Failure']]],
                    ],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'sourceIPAddress.keyword']]]]],
                ],
                'usage' => [
                    'uri' => "${service_id}_",
                    'query_bool' => ['must_not' => [['match' => ['userAgent.keyword' => '[AWSConfig]']]]],
                    'aggs' => ['group_by_tenant' => ['terms' => ['field' => 'tenant.keyword'], 'aggs' => ['group_by_ip' => ['terms' => ['field' => 'sourceIPAddress.keyword']]]]],
                ],
            ];
            break;
        default:
            return;
    }
    return $filter;
}

function _insert_activity_info($reportDb, $beginTime, $endTime)
{
    global $conf;
    global $log;
    $log->info("_insert_activity_info(reportDb, $beginTime, $endTime)");

    $rv = _elasticsearch_search('/_aliases', [], 'GET');
    $aliases = array_keys($rv);
    $services = [];
    foreach ($aliases as $index) {
        if (preg_match('/serviceaudit_([^_]+)_/', $index, $matches)) {
            if (in_array($matches[1], $services) === false) {
                array_push($services, $matches[1]);
            }
        }
    }

    $insertval = [];
    $aggregate = [];
    $locations = [];

    foreach ($services as $service) {
        $activities = _get_activity_filter($service);
        foreach ($activities as $activity => $reqDetail) {
            list($request_uri, $request_data) = _elasticsearch_prepare($reqDetail, $beginTime, $endTime);
            $result = _elasticsearch_search($request_uri, $request_data);

            if (isset($result['aggregations']) && isset($result['aggregations'])) {
                $service_aggs = $result['aggregations'];
                foreach ($service_aggs['group_by_tenant']['buckets'] as $tenant_aggs) {
                    $entry = [
                        'tenant' => $tenant_aggs['key'],
                        'date' => substr($beginTime, 0, 10),
                    ];
                    foreach ($tenant_aggs['group_by_ip']['buckets'] as $tenant_ip_aggs) {
                        list($country_code, $longitude, $latitude) = ip2Locations($conf['geoip'], $tenant_ip_aggs['key']);
                        if (!isset($locations[$country_code])) {
                            $locations[$country_code] = [$longitude, $latitude];
                        }
                        $domain = '-';

                        // Aggregate records by primary key
                        $primary = $entry['tenant'].' '.$entry['date'].' '.$service.' '.$activity.' '.$country_code.' '.$domain;
                        if (isset($aggregate[$primary])) {
                            $aggregate[$primary] += $tenant_ip_aggs['doc_count'];
                        } else {
                            $aggregate[$primary] = $tenant_ip_aggs['doc_count'];
                        }
                    }
                }
            } else {
                while (isset($result['hits']) && isset($result['hits']['hits']) && count($result['hits']['hits'])) {
                    $log->debug($service." \t".$activity." \t\tfetched: ".count($result['hits']['hits'])." \ttotal: ".$result['hits']['total']['value']);
                    foreach ($result['hits']['hits'] as $hit) {
                        // Process each records for each service
                        $entry = _elasticsearch_process($service, $activity, $hit['_source']);

                        list($country_code, $longitude, $latitude) = ip2Locations($conf['geoip'], $entry['ip']);
                        if (!isset($locations[$country_code])) {
                            $locations[$country_code] = [$longitude, $latitude];
                        }
                        $domain = $entry['domain'] ? $entry['domain'] : '-';

                        // Aggregate records by primary key
                        $primary = $entry['tenant'].' '.$entry['date'].' '.$service.' '.$activity.' '.$country_code.' '.$domain;
                        if (isset($aggregate[$primary])) {
                            $aggregate[$primary] += 1;
                        } else {
                            $aggregate[$primary] = 1;
                        }
                    }
                    $scroll_uri = '/_search/scroll';
                    $scroll_data = [
                        'scroll' => '1m',
                        'scroll_id' => $result['_scroll_id'],
                    ];
                    $result = _elasticsearch_search($scroll_uri, $scroll_data);
                }

                if (isset($result['_scroll_id'])) {
                    $scroll_uri = '/_search/scroll';
                    $scroll_data = [
                        'scroll_id' => $result['_scroll_id'],
                    ];
                    $result = _elasticsearch_search($scroll_uri, $scroll_data, 'DELETE');
                }
            }
        }
    }

    foreach ($aggregate as $primary => $count) {
        list($tenant, $date, $service, $activity, $country_code, $domain) = explode(' ', $primary);
        list($longitude, $latitude) = $locations[$country_code];
        $insertval[] = [$reportDb->quote($tenant),  $reportDb->quote($date), $reportDb->quote($service), $reportDb->quote($activity), $reportDb->quote($country_code), $reportDb->quote($longitude), $reportDb->quote($latitude), $reportDb->quote($domain), $reportDb->quote($count)];
    }

    try {
        $reportDb->beginTransaction();
        foreach ($insertval as $values) {
            $sql = 'INSERT INTO activity_info (tenant, date, service, activity, country_code, longitude, latitude, domain, number) VALUES ('.implode(', ', $values).') ON DUPLICATE KEY UPDATE number = VALUES(number), longitude = VALUES(longitude), latitude = VALUES(latitude)';
            $log->debug('File: '.__FILE__.' Line: '.__LINE__.' '.$sql);
            $reportDb->prepare($sql)->execute();
        }
        $reportDb->commit();
    } catch (Exception $e) {
        $log->err('File: '.__FILE__.' Line: '.__LINE__.' '.$sql.':'.$e->getMessage());
        $reportDb->rollback();
    }
}

function _create_report($reportDb, $beginTime)
{
    _insert_activity_info($reportDb, $beginTime.'T00:00:00+0900', $beginTime.'T23:59:59+0900');
}

function _delete_old_data($reportDb, $cutoffTime)
{
    // TODO Delte old data on cutoffTime
}

function ip2Locations($db_file, $ip)
{
    $geo = new \IP2Location\Database($db_file, \IP2Location\Database::FILE_IO);

    if ($ip) {
        if (preg_match('/\[(.+)\]:/', $ip, $matches)) {
            $ip = $matches[1];
        } elseif (preg_match('/^([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}):/', $ip, $matches)) {
            $ip = $matches[1];
        }
        $records = $geo->lookup($ip, \IP2Location\Database::ALL);

        $country_code = isset($records['countryCode']) && trim($records['countryCode']) ? trim($records['countryCode']) : '-';
        $longitude = isset($records['longitude']) && trim($records['longitude']) ? trim($records['longitude']) : '';
        $latitude = isset($records['latitude']) && trim($records['latitude']) ? trim($records['latitude']) : '';
    } else {
        $country_code = '-';
        $longitude = '';
        $latitude = '';
    }

    return [$country_code, $longitude, $latitude];
}

function main($argv)
{
    global $log;
    global $conf;

    // レポートのデータベース
    $db_conn = 0;
    $db_user = $conf['db_report_user'];
    $db_pass = $conf['db_report_password'];
    $db_name = $conf['db_report_schema'];
    $db_hosts = explode(' ', $conf['db_report_host']);
    ini_set('mysql.connect_timeout', isset($conf['db_timeout']) ? $conf['db_timeout'] : 10);
    foreach ($db_hosts as $db_host) {
        try {
            $db_conn++;
            $port = '';
            if (strpos($db_host, ':')) {
                $hostinfo = explode(':', $db_host);
                $db_host = $hostinfo[0];
                $port = $hostinfo[1];
            }
            $dsn = "mysql:host=$db_host;".($port ? "port=$port;" : '')."dbname=$db_name;charset=utf8";
            $reportDb = new PDO($dsn, $db_user, $db_pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            break;
        } catch (PDOException $e) {
            $log->err("initialize failed($dsn): ".$e->getMessage());
        }
    }
    if (!$reportDb && $db_conn == count($db_hosts)) {
        $log->err("initialize failed: Can't connect DB");
        exit;
    }

    $argvTime = isset($argv[1]) ? $argv[1] : 0;
    $lastTime = is_file(LAST_EXECUTION_DATE) ? file_get_contents(LAST_EXECUTION_DATE) : 0;
    $baseTime = date('Y-m-d');
    if (is_numeric($argvTime) && $argvTime > 0 && $argvTime <= 7) {
        // 引数が指定されたら指定された日数以降のレポートデータを作成
        $beginTime = date('Y-m-d', strtotime($baseTime." -$argvTime day"));
    } elseif ($lastTime && $lastTime != $baseTime) {
        // 前回起動日時以降のレポートデータを作成
        //$beginTime = $lastTime;
        $beginTime = date('Y-m-d', strtotime($lastTime.' -3 day'));
    } else {
        // 標準では3日前からのレポートを作成（アクティビティログ最大3日まで遅れる）
        $beginTime = date('Y-m-d', strtotime($baseTime.' -3 day'));
    }

    // 開始日時から1日毎レポートを作成する。
    while ($beginTime < $baseTime) {
        _create_report($reportDb, $beginTime);
        $beginTime = date('Y-m-d', strtotime($beginTime.' +1 day'));
    }

    // 古いログデータの削除
    $cutoffTime = isset($conf['cut_off_month']) ? $conf['cut_off_month'] : 18;
    _delete_old_data($reportDb, $cutoffTime);

    $reportDb = null;

    // 起動日時記録
    file_put_contents(LAST_EXECUTION_DATE, $baseTime);
}

$log->info("start $logid ".implode(' ', $argv));
main($argv);
$log->info("end $logid");
