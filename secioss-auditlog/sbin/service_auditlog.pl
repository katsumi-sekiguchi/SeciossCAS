#!/usr/bin/perl

use strict;
use warnings;
use POSIX ();
use Fcntl;
use Net::LDAP;
use Config::General;
use DateTime;
use DateTime::Format::Strptime;
use DateTime::Format::HTTP;
use Time::HiRes qw/ gettimeofday /;
use Fcntl qw(:DEFAULT :flock);
use Sys::Syslog;
use File::Basename;
use File::Path;
use File::Copy;
use JSON;
use LWP::UserAgent;
use HTTP::Request::Common;
use PHP::Serialization qw(serialize unserialize);
use Getopt::Std;
use Data::Dumper;

use Secioss::Audit;

# git:SeciossLink/identitymanager/src/LISM-enterprise/lib/LISM/Utils/secioss_util.pl
require 'LISM/Utils/secioss_util.pl';

#
# Options
# t : Run target tenant.
# s : target service
my %opt;
getopts("t:s:m:hf", \%opt);

my $OPT_TENANT = defined($opt{'t'}) ? $opt{'t'} : undef;
my $OPT_SERVICE = defined($opt{'s'}) ? $opt{'s'} : undef;
my $OPT_FORCE_START = defined($opt{'f'}) ? $opt{'f'} : 0;


#### CONSTANTS ####
my @basename  =  split(/\//, $0);
my $basename  =  pop(@basename);
$basename     =~ s/.[a-z, 0-9]+$//;
# 親プロセス名(psコマンド)
$0            =  $basename;
my $MYNAME = $basename;
my %SERVICES = (
    'GoogleApps_login' => 'googleapps',
    'GoogleApps_admin' => 'googleapps',
    'GoogleApps_drive' => 'googleapps',
    'GoogleApps_mobile' => 'googleapps',
    'GoogleApps_token' => 'googleapps',
    'Office365' => 'office365',
    'Dropbox' => 'dropbox',
    'Box' => 'box',
    'AWS' => 'aws',
    'LineWorks_admin' => 'lineworks',
    'LineWorks_auth' => 'lineworks',
    'LineWorks_home' => 'lineworks',
    'LineWorks_drive' => 'lineworks',
    'LineWorks_calendar' => 'lineworks',
    'LineWorks_contact' => 'lineworks',
    'LineWorks_form' => 'lineworks',
    'LineWorks_share' => 'lineworks',
    'LineWorks_note' => 'lineworks',
    'LineWorks_received-mail' => 'lineworks',
    'LineWorks_message' => 'lineworks',
    'LineWorks_sent-mail' => 'lineworks',
    'Salesforce' => 'salesforce',
);
my %CASB_SERVICES = (
    # Office365だけはモジュール側で判断する
    # 'Office365' => 'office365'
    'GoogleApps_drive' => 'googleapps',
    'GoogleApps_mobile' => 'googleapps',
    'GoogleApps_token' => 'googleapps'
);

#### PROCESSING ####

# 多重起動のチェック用
# pgrep の -u オプションには起動するユーザー名を指定
my $CMD = {
            grep  => '/usr/bin/grep',
            pgrep => '/bin/pgrep -fo -u root',
            kill  => '/bin/kill',
        };
my $CHROOT  = "/opt/secioss/var/lib/service_auditlog";
my $FAILUED_PATH    = "$CHROOT/failued";
my $OPTION  = $ARGV[0];

#### Configuration ###
my $conf_file = '/opt/secioss/etc/service_auditlog.conf';
my $conf = Config::General->new($conf_file );
my %conf = $conf->getall;

#### Process ###
my $CHILD_NUM = 0;
my $CHILD_MAX = defined $conf{'max_process'} ? $conf{'max_process'} : 3;

#### LDAP ###
my $LDAP_HOST = $conf{'ldap_uri'};
my $LDAP_USER = $conf{'ldap_user'};
my $LDAP_PASSWORD = $conf{'ldap_password'};
my $LDAP_BASEDN = $conf{'ldap_basedn'};
if(!$LDAP_HOST || !$LDAP_USER || !$LDAP_PASSWORD || !$LDAP_BASEDN){
    _err("$MYNAME:ldap_infomation not found");
    exit 1;
}

#### Elasticsearch ###
my $Elasticsearch_URL = $conf{'elasticsearch_url'};
if(!$Elasticsearch_URL){
    _err("$MYNAME:elasticsearch_url not found");
    exit 1;
}
if($Elasticsearch_URL =~ /\/$/){
    chop $Elasticsearch_URL;
}
my $Elasticsearch_URI = $Elasticsearch_URL;
my $ELASTICSEARCH_RETRY_COUNT = defined $conf{'elasticsearch_retry_count'} ? $conf{'elasticsearch_retry_count'} : 3;
my $BULK_FILE_SIZE = defined $conf{'elasticsearch_bulk_size'} ? $conf{'elasticsearch_bulk_size'} : 10485760;

#### Others ###
our $DECRYPT_KEY = getSecretKey($conf{'decrypt_key'});
my $DAYS_TO_EXTRACT = defined $conf{'days_to_extract'} ? $conf{'days_to_extract'}: 30;

### SUBROUTINE ###
sub _usage {
    my $msg   = shift;
    print <<"EOS";

    Usage:$basename [-h] [-t tenant] [-s service]
        Options:
            -h: View Help
            -f: Force start. This option does not check for process duplication.
            -t: Target tenant.
            -s: Target service

        Services:
EOS
    foreach my $service_name (sort keys(%SERVICES)) {
        print "             $service_name\n";
    }
    print "\n";
}

sub _auditOutput {
    my $msg   = shift;

    openlog( $MYNAME, 'pid', 'local3' );
    syslog( 'info', $msg );
    closelog();
}

sub _output {
    my $level   = shift;
    my $msg     = shift;
    my $pid=$$; #プロセスIDを取得

    openlog( $MYNAME, 'pid', 'local4' );
    syslog( $level, "pid=$pid, ".$msg );
    closelog();
}

sub _debug {
    my $msg = shift;
    my $tenant  = shift;
    if(defined $tenant){
        $msg = "$tenant, $msg";
    }

    _output( 'debug', $msg );
}

sub _info {
    my $msg = shift;
    my $tenant  = shift;
    if(defined $tenant){
        $msg = "$tenant, $msg";
    }

    _output( 'info', $msg );
}

sub _err {
    my $msg = shift;
    my $tenant  = shift;
    if(defined $tenant){
        $msg = "$tenant, $msg";
    }

    _output( 'err', $msg );
}
sub _auditerr {
    my $msg = shift;

    _auditOutput( $msg );
}


##
##  _getLdapConnect
##  LDAP接続
##
sub _getLdapConnect
{
    my ($uri, $binddn, $bindpw) = @_;

    my $ldap = Net::LDAP->new($uri);
    if (!defined($ldap)) {
        return undef;
    }

    my $msg = $ldap->bind($binddn, password => $bindpw);
    if ($msg->code) {
        return undef;
    }

    return $ldap;
}

##
##  _get_ldap_info
##  取得したテナント名とサービス名を基にLDAPから必要な情報を取得する
##
sub _get_ldap_info
{
    my ($ldap, $host, $basedn) = @_;

    my $ldapMetadata = $ldap->search(
        base => $basedn,
        filter => "(&(objectClass=account)(host=$host*)(description;x-type=activitylog)(seciossAccountStatus=active))",
    );

    my $errcode = $ldapMetadata->code;
    if ($errcode) {
        _err("Searching tenant with audit log enabled failed: ".$ldapMetadata->error."($errcode)");
        return -1;
    }

    my @list = ();
    if ($ldapMetadata->count) {
        foreach my $entry ($ldapMetadata->entries) {
            my %data = ();
            $data{'dn'} = $entry->dn;
            if ($entry->dn =~ /(?:.*,o=)(.+)(?:,$LDAP_BASEDN.*)/i) {
                $data{'tenant'} = $1;
            }
            if (defined $OPT_TENANT && $OPT_TENANT ne $data{'tenant'}) {
                # テナント指定の時は、対象テナントだけ
                next;
            }
            foreach my $attr ($entry->attributes) {
                my $value = $entry->get_value($attr);
                if ($attr =~ /^seciossEncryptedPassword/i) {
                    $value = decrypt($value, $DECRYPT_KEY, 'aes');
                }
                $data{lc($attr)} = $value;
            }
            if ($host =~ /^box/) {
                # BOXのときはアクセストークンを取得して更新されたリフレッシュトークン格納
                my ($access_token, $refresh_token) = _box_refreshToken(\%data);
                if (!defined $refresh_token || ! $refresh_token) {
                    _err("Box token refresh failed: $host".(defined($data{'tenant'}) ? ' '.$data{'tenant'} : ''));
                    next;
                }
                $refresh_token = encrypt($refresh_token, $DECRYPT_KEY, 'aes');
                my $res = $ldap->modify(
                    $data{'dn'},
                    replace => {'seciossencryptedpassword;x-token' => $refresh_token}
                );
                if ($res->code) {
                    _err("Failed to save Box token($refresh_token): $host".(defined($data{'tenant'}) ? ' '.$data{'tenant'} : ''));
                    next;
                }
                $data{'access_token'} = $access_token;
            }

            push(@list, \%data);
        }
    }
    return \@list;
}

##
## _box_refreshToken
## アクセストークンを取得して更新されたリフレッシュトークンも返却
##
##
sub _box_refreshToken
{
    my ($info) = @_;

    my $ua = LWP::UserAgent->new;
    my %params = (
        'grant_type' => 'refresh_token',
        'refresh_token' => $info->{'seciossencryptedpassword;x-token'},
        'client_id' => $info->{'uid'},
        'client_secret' => $info->{'seciossencryptedpassword;x-secret'},
    );
    my $res = $ua->post($info->{'description;x-url-token'}, [%params]);
    unless ($res->is_success()) {
        return;
    }
    my $json = decode_json($res->content);
    if (!defined($json->{'refresh_token'}) || !defined($json->{'access_token'})) {
        return;
    }

    return ($json->{'access_token'}, $json->{'refresh_token'});
}

##
##  _is_casb
##  テナントにCASB機能が割り当たっているかLDAPへ検索を行う
##
sub _is_casb
{
    my ($ldap, $tenant, $basedn) = @_;
    my $serchdn = defined $tenant && $tenant ne "" ? "o=$tenant," : "";
    my $ldapMetadata = $ldap->search(
        base => $serchdn . $basedn,
        filter => "(&(seciossTenantStatus=active)(seciossAllowedFunction=casb))",
    );

    my $errcode = $ldapMetadata->code;
    if ($ldapMetadata->count) {
        return 1;
    }
    return 0;
}

##
##  _is_casb_function
##  CASB機能でしか検索しないアクティビティログかどうか判定する
##
sub _is_casb_function
{
    my ($service_name) = @_;

    if($CASB_SERVICES{$service_name}){
        return 1;
    }
    return 0;
}

##
##  _set_start_time
##  Elasticsearchに格納したログデータの最終取得時間を返す
##  データがない場合は空値
##
sub _set_start_time {
    my ($tenant_name, $service_id) = @_;

    my $url = $Elasticsearch_URI.'/serviceaudit_'.lc($service_id).'*_'.lc($tenant_name).'_*/_search?size=1';
    my $ua = LWP::UserAgent->new;
    my $content = encode_json({
        "sort" =>[{
            '@timestamp' => {
                "order" => "desc"
            }
        }]
    });
    my $request = HTTP::Request->new(POST => $url);
    $request->header("Content-Type" => "application/json");
    $request->content($content);
    my $response = $ua->request($request);
    if ($response->is_success) {
        my $result = decode_json($response->content);
        if($result->{'hits'}->{'total'}->{'value'}){
            my $datetime = DateTime::Format::HTTP->parse_datetime($result->{'hits'}->{'hits'}[0]->{'_source'}->{'@timestamp'});
            my $limittime = DateTime->now->subtract( days => $DAYS_TO_EXTRACT);
            if ($datetime->epoch < $limittime->epoch) {
                $datetime = $limittime;
            }
            return $datetime->set_time_zone('UTC')->datetime.'Z';
        }
        my $datetime = DateTime->now();

        return $datetime->subtract( days => $DAYS_TO_EXTRACT ).'Z';
    }

    return;
}

##
##  _double_check_auditlog
##  重複チェック
##  APIを利用して収集したデータが既にElasticsearchに存在するか確認する処理
##  データが存在する場合は1、存在しない場合は0を返す
##
sub _double_check_auditlog {
    my ($service_id, $row, $tenant_name) = @_;

    my $url = $Elasticsearch_URI.'/serviceaudit_'.lc($service_id).'*_'.lc($tenant_name).'_*/_search';
    my $ua = LWP::UserAgent->new;
    my $content = encode_json({
        "query" =>{
            'term' => {
                "double_check_value.keyword" => $row->{'double_check_value'}
            }
        }
    });
    my $request = HTTP::Request->new(POST => $url);
    $request->header("Content-Type" => "application/json");
    $request->content($content);
    my $response = $ua->request($request);
    if ($response->is_success) {
        my $result = decode_json($response->content);
        if($result->{'hits'}->{'total'}->{'value'}){
            return 1;
        }
    }
    return 0;
}

##
##  _create_bulk_file
##  Bulk APIのリクエスト用ファイル作成
##  リクエストを一括で行うためのファイルを作成する
##
sub _create_bulk_file {
    my ($service_id, $tenant_name, @data) = @_;
    my $recovery_path = "$FAILUED_PATH/$service_id/$tenant_name";
    my $file_path = "$recovery_path/bulk_$service_id.json";
    # 失敗ファイル保管ディレクトリ作成
    if (!-d "$recovery_path"){
        mkpath("$recovery_path", {chmod => 0775});
    }
    my $json_data = encode_json(\@data);
    open(DATAFILE, ">>", $file_path) or die("Error:$!");
    print DATAFILE $json_data."\n";
    close(DATAFILE);
    return 0;
}

##
## _bulk_format
## array in hash型のデータをElasticSearchのBulk API用に整形を行う
##
sub _bulk_format {
    my ($service_name, $tenant_name, @auditlog) = @_;
    my $bulk_data = "";
    foreach my $row (@auditlog) {
        my $set_log_date = $row->{'@timestamp'};
        if ($set_log_date =~ /^(.*)(T.*)/) {
            $set_log_date = $1;
        }
        $set_log_date =~ s/-/\./g;
        my $index = encode_json({ "index" => { "_index" => 'serviceaudit_'.lc($service_name).'_'.lc($tenant_name).'_'.$set_log_date}});
        $row->{'tenant'} = $tenant_name;
        my $field_data = encode_json($row);
        $bulk_data .= $index."\n".$field_data."\n";
    }
    return $bulk_data;
}

##
##  _send_auditlog
##  Elasticsearchにデータを送信する処理
##
sub _send_auditlog {
    my ($json) = @_;

    my $url = $Elasticsearch_URI.'/_bulk';
    my $ua = LWP::UserAgent->new;
    my $request = HTTP::Request->new(POST => $url);
    $request->header("Content-Type" => "application/x-ndjson");
    $json =~ s/"\.([^"]+)":/"$1":/g;
    $json =~ s/"([^"]+)\.":/"$1":/g;

    $request->content($json);
    my $response = $ua->request($request);
    my $error;
    if ($response->is_success) {
        # 成功した場合、Bulkリクエスト内でエラーになっていないかチェック
        my $result;
        eval {
            $result = decode_json($response->content);
        };
        if ($@) {
            $error = $@;
        }
        if($result->{'errors'} eq JSON::true){
            $error = defined($result->{'items'}->[0]->{'index'}->{'error'}->{'reason'}) ? $result->{'items'}->[0]->{'index'}->{'error'}->{'reason'} : 'Unknown';
        }
    } else {
        $error = $response->message.'('.$response->code.')';
    }

    if (!defined($error)) {
        # Success
        return 0;
    }
    return $error;
}

##
##  _resend_auditlog
##  Elasticsearchにデータを再送信する処理
##
sub _resend_auditlog {

    my ($service_id, $tenant_name) = @_;

    if (!-d "$FAILUED_PATH/$service_id/$tenant_name") {
        return 1;
    }

    # 失敗ファイル一覧を取得し、再送
    my @send_file_list = glob("$FAILUED_PATH/$service_id/$tenant_name/*");
    if ($#send_file_list == 0) {
        # 何もしない
    } elsif($#send_file_list == -1) {
        return 1;
    } else {
        _err("Failed to resend ${service_id}_auditlog: multiple bulk file exists. ", $tenant_name);
        foreach my $file(@send_file_list) {
            unlink($file);
        }
        return;
    }

    # 基本的に一つのみ入る想定
    my $send_file = $send_file_list[0];

    open(my $FH, "<", $send_file) or die;
    my $json = do { local $/; <$FH> };
    my $auditlog_json;
    eval {
        $auditlog_json = decode_json($json);
    };
    if ($@) {
        unlink($send_file);
        _err("Failed to resend ${service_id}_auditlog: Failure to parse bulk file($send_file). ", $tenant_name);
        return;
    }
    # 形式をarray of hashesに変換する
    my @auditlog;
    foreach my $row (@{ $auditlog_json }) {
        push @auditlog, $row;
    }

    my $total_entry = $#auditlog+1;
    if ($total_entry == 0) {
        unlink($send_file);
        return 1;
    }
    my $duplicate_entry = 0;
    my $parse_fail_count = 0;

    _info("Resending ${service_id}_auditlog: Log total count[$total_entry]. ", $tenant_name);
    for my $i (reverse 0 .. $#auditlog) {
        my $row = $auditlog[$i];
        eval {
            encode_json($row);
        };
        if ($@) {
            $parse_fail_count ++;
            splice(@auditlog, $i, 1);
            next;
        }

        # 重複したログは削除
        if (_double_check_auditlog($service_id, $row, $tenant_name)) {
            splice(@auditlog, $i, 1);
            $duplicate_entry ++;
            next;
        }
    }

    my $entry = $#auditlog+1;
    if ($entry == 0) {
        unlink($send_file);
        return 1;
    }
    my $bulk_data = _bulk_format($service_id, $tenant_name, @auditlog);
    my $error = _send_auditlog($bulk_data);
    if ($error) {
        _err("Failed to resend ${service_id}_auditlog. Log count active[$entry], duplicates[$duplicate_entry], fails[$parse_fail_count]: $error", $tenant_name);
        unlink($send_file);
        # 失敗時はバルクファイルを再作成する
        if (_create_bulk_file($service_id, $tenant_name, @auditlog)){
            _err("Failed to recreating Bulk File.", $tenant_name);
        };
        return;
    }
    _info("Register result ${service_id}_auditlog: Log count active[$entry], duplicates[$duplicate_entry], fails[$parse_fail_count]. ", $tenant_name);
    unlink($send_file);
    return 1;
}

##
##  _get_auditlog_process
##  子プロセスで監査ログ取得する処理
##
sub _get_auditlog_process {
    my ($module, $LDAP_info, $service_name, $opt) = @_;

    my $service_id = $service_name;
    if ($LDAP_info->{'host'} =~ /^(?:.+)(0[0-9]+)$/) {
        my $idx = $1;
        if ($service_id =~ /^([^_]+)(_.+)$/) {
            $service_id = $1.$idx.$2;
        } else {
            $service_id .= $idx;
        }
    }
    my $tenant_name = defined($LDAP_info->{'tenant'}) ? $LDAP_info->{'tenant'} : '';
    my $audit = new $module(%$LDAP_info);
    if (!$audit) {
        _err("Failed to Create ${service_id} object.", $tenant_name);
        return;
    }
    my $start_time = &_set_start_time($tenant_name, $service_id);
    if (!defined($start_time) || !$start_time) {
        _err("Failed to fetch start time ${service_id}_auditlog: Can't connect to log server.", $tenant_name);
        return;
    }
    _info("Acquire the audit log of ${service_id}. Start acquiring from ${start_time}.", $tenant_name);
    my $auditlog_result = $audit->getAudit($start_time, $opt, $LDAP_info->{'is_casb'});
    if (!$auditlog_result) {
        _err("Failed to Collect ${service_id}_auditlog: ".$audit->{_error}, $tenant_name);
        _auditMessage($tenant_name, 'System', 'modify', $LDAP_info->{'dn'}, 1, $audit->{_error}, $service_id);
        return;
    } else {
        if ($audit->{_info}) {
            _info("${tenant_name} ".$audit->{_info}, $tenant_name);
        }
        _info("Collect ${service_id}_auditlog", $tenant_name);
    }
    unless ($audit->{_audit}) {
       return;
    }
     return @{$audit->{_audit}};
}

##
##  _set_auditlog_process
##  子プロセスで監査ログ送信する処理
##
sub _set_auditlog_process {
    my ($service_id, $tenant_name, @auditlog_result) = @_;
    my $send_false_flag = 0;
    my $duplicate_entry = 0;
    my $parse_fail_count = 0;
    my $total_entry = $#auditlog_result+1;
    if ($total_entry == 0) {
        return 1;
    }
    _info("Sending ${service_id}_auditlog: Log total count[$total_entry]. ", $tenant_name);
    for my $i (reverse 0 .. $#auditlog_result) {
        my $row = $auditlog_result[$i];
        eval {
            encode_json($row);
        };
        if ($@) {
            $parse_fail_count ++;
            splice(@auditlog_result, $i, 1);
            next;
        }

        # 重複したログは削除
        if (_double_check_auditlog($service_id, $row, $tenant_name)) {
            splice(@auditlog_result, $i, 1);
            $duplicate_entry ++;
            next;
        }
    }

    my $entry = $#auditlog_result+1;
    if ($entry == 0) {
        return 1;
    }
    my $bulk_data = _bulk_format($service_id, $tenant_name, @auditlog_result);
    my $error = _send_auditlog($bulk_data);
    if ($error) {
        _err("Failed to send ${service_id}_auditlog. Log count active[$entry], duplicates[$duplicate_entry], fails[$parse_fail_count]: $error", $tenant_name);
        if (!@auditlog_result) {
            return;
        }
        # 失敗時はバルクファイルを作成する
        if (_create_bulk_file($service_id, $tenant_name, @auditlog_result)){
            _err("Failed to create Bulk File.", $tenant_name);
        };
        return;
    }
    _info("Register result ${service_id}_auditlog: Log count active[$entry], duplicates[$duplicate_entry], fails[$parse_fail_count]. ", $tenant_name);
    return 1;
}

##
##  _child_process
##  子プロセス処理
##  この処理は「exit」させる
##
sub _run_child_process {
    my ($module, $LDAP_info, $service_name, $tenant_name, $opt) = @_;

    my $service_id = $service_name;
    if ($LDAP_info->{'host'} =~ /^(?:.+)(0[0-9]+)$/) {
        my $idx = $1;
        if ($service_id =~ /^([^_]+)(_.+)$/) {
            $service_id = $1.$idx.$2;
        } else {
            $service_id .= $idx;
        }
    }

    _info("$service_id start.", $tenant_name);
    $0 = "$MYNAME $service_id $tenant_name"; # 子プロセス名を設定(psコマンド)

    # 前回送信失敗ログの送信
    if (!_resend_auditlog($service_id, $tenant_name)) {
        # 再送信失敗したらそのテナントのそのサービスの処理はスキップ
        exit 1;
    }

    # 監査ログ収集
    my @auditlog_result = _get_auditlog_process($module, $LDAP_info, $service_name, $opt);
    if( !@auditlog_result ){
        exit 1;
    }

    # 収集した監査ログをElasticsearchへ登録する
    if(!_set_auditlog_process($service_id, $tenant_name, @auditlog_result)){
        _err("Failed to register the audit log.", $tenant_name);
        exit 1;
    }
    _info("$service_id end.", $tenant_name);
    exit 0;
}

##
##  _check_run
##  プロセスチェックと起動を行う
##
sub _check_run {
    my $run;
    my $pid=$$; #プロセスIDを取得
    my $ppid=getppid(); #呼び出し元プロセスID
    my $exit_code = 0;
    if ( $pid ne 0 ) {
        # 親プロセス処理
        _info("start $MYNAME");
    }

    $run = `$CMD->{pgrep} '^$basename' | $CMD->{grep} -v $pid | $CMD->{grep} -v $ppid`;
    chomp( $run );

    # 親プロセスの起動
    if ( $run eq "" || $OPT_FORCE_START == 1) {
        _info("wake up process");
        # MAIN起動
        $exit_code = &_run( $pid );
    } else {
        # stop が指定された場合は親プロセスを kill
        if ( defined($OPTION) && $OPTION =~ /^stop$/ ) {
            `$CMD->{kill} $run`;
            _info(" $basename\[$run\] is command stop.");
            exit 0;
        # オプションが指定されていなければ親プロセスの pid を返す
        } else {
            _err(" $basename\[$run\] is already running.");
            exit 0;
        }
    }
    if ( $pid ne 0 ) {
        # 親プロセス処理
        _info("end $MYNAME");
    }
    return $exit_code;
}

sub _auditMessage
{
    my ($tenant, $modifier, $op, $dn, $result, $error, $servicename) = @_;
    my $service;
    my $entry;
    if ($dn =~ /^host=([^,]*),ou=([^,]*),o=$tenant,${LDAP_BASEDN}$/) {
        $service = $1;
        $entry = $2;
    }
    my $logdata = "$tenant; $modifier; $result; $service; $entry; ip=127.0.0.1 user=\"$modifier\" type=$op dn=\"$dn\" result=$result servicename=\"$servicename\" error=\"$error\"";
    if ($service && $entry) {
        _auditOutput($logdata);
    }
}

##
##  _run
##  親プロセス
##  メイン処理とプロセス監視
##
sub _run {
    ##
    ##  main
    ##  監査ログを取得するテナント名をサービス名を参照して取得する
    ##
    my ($pid, $wait_pid);
    _info("Start audit log collection processing.");
    foreach my $service_name (keys(%SERVICES)) {
        my $ldap = _getLdapConnect($LDAP_HOST, $LDAP_USER, $LDAP_PASSWORD);
        if (!$ldap) {
            _err('FILE: ' . __FILE__ . ' LINE: ' . __LINE__ . ' Ldap connect error: ' . $1);
            exit 1;
        }

        if(defined $OPT_SERVICE && $OPT_SERVICE ne $service_name){
            # 指定されたサービスのみ実行
            next;
        }

        my $host = $SERVICES{$service_name};
        my $opt = undef;
        my $module = $service_name;
        if (index($service_name, '_')) {
            ($module, $opt) = split(/_/, $service_name, 2);
        }
        require 'Secioss/Audit/'.$module.'.pm';
        $module = 'Secioss::Audit::'.$module;
        _info("do ${service_name}_auditlog");

        my $LDAP_data = &_get_ldap_info($ldap, $host, $LDAP_BASEDN);
        if (ref($LDAP_data) ne 'ARRAY') {
            _err("Failed to Get ${service_name} config");
            next;
        }

        # Tenant毎の処理
        foreach my $LDAP_info (@$LDAP_data) {
            my $tenant_name = defined($LDAP_info->{'tenant'}) ? $LDAP_info->{'tenant'} : '';
            _info("$service_name waiting...", $tenant_name);

            # CASB機能がテナントで有効化検索
            my $ldap_casb = _getLdapConnect($LDAP_HOST, $LDAP_USER, $LDAP_PASSWORD);
            if (!$ldap_casb) {
                _err('FILE: ' . __FILE__ . ' LINE: ' . __LINE__ . ' Ldap connect error: ' . $1, $tenant_name);
                exit 1;
            }
            my $is_casb = &_is_casb($ldap_casb, $tenant_name, $LDAP_BASEDN);
            if ($is_casb == -1) {
                _err("Failed to search CASB function.", $tenant_name);
                next;
            }

            # 特定の機能はCASB有効時のみログ収集
            if($is_casb == 0 && &_is_casb_function($service_name) == 1){
                # CASB機能がOFF、且つCASB用のサービスであれば取得しない
                _info("Don't get $service_name [non-CASB mode]", $tenant_name);
                next;
            }
            $LDAP_info->{'is_casb'} = $is_casb;

            # 子プロセスを作成
            my $pid = fork;
            die "Cannot fork: $!" unless defined($pid);

            if ( $pid ne 0 ) {
                # 子プロセス管理
                $CHILD_NUM++;
            } elsif ( defined($pid) ) {
                #---------------------------
                # 子プロセスの処理 開始
                #---------------------------
                &_run_child_process($module, $LDAP_info, $service_name, $tenant_name, $opt);
                #---------------------------
                # 子プロセスの処理 終了
                #---------------------------
            } else {
                _err("Failed to $tenant_name process start.", $tenant_name);
                exit 1;
            }

            # 子プロセスの管理
            # 起動子プロセスが $CHILD_MAX まで達したら子プロセスの生成を停止
            if ($CHILD_NUM == $CHILD_MAX) {
                $wait_pid = wait;
                $CHILD_NUM--;
            }
        }
        _info("end ${service_name}_auditlog");
    }

    # 子プロセスのWait
    my $exit_code = 0;
    while ( 1 ) {
        # 子プロセスが存在するか
        if($CHILD_NUM == 0){
            last;
        }
        # 全ての子プロセスが終了するまで待機
        $wait_pid = wait;
        # DEBUG
        if(!$pid){$pid = 0;}

        # print "\n親プロセス( 子プロセスID: $pid )\n";
        my $exit_value = $? >> 8;
        my $dumped_core = $? & 128;
        my $signal_num = $? & 127;
        my $is_finished = WIFEXITED( $? );
        # print "子プロセスの終了コード: $exit_value\n";
        # print "コアダンプが発生したかどうか : $dumped_core\n";
        # print "子プロセスを終了させたシグナル : $signal_num\n";
        # print "子プロセスが終了したかどうか : $is_finished\n";
        $CHILD_NUM--;
        if ($CHILD_NUM == 0) {
            _info("All process terminate.");
            last;
        }
        if ($dumped_core != 0){
            _err("Fatal error! ! A core dump has occurred. pid[$pid]");
            die;
        }
    }
    return $exit_code;
}

#---------------------------
# メインプロセス 開始
#---------------------------
if( defined $opt{'h'} ){
    &_usage();
    exit;
}
my $exit_code = &_check_run( $OPTION );
exit $exit_code;