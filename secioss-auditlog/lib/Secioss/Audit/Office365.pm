package Secioss::Audit::Office365;

use strict;
use warnings;
use Sys::Syslog;
use JSON;
use LWP::UserAgent;
use HTTP::Request::Common qw(POST);
use Data::Dumper;
use base qw(Secioss::Audit);

use constant {
    AUTH_URL => 'https://login.microsoftonline.com',
    API_URL => 'https://manage.office.com',
    RESOURCE => 'https://manage.office.com',
    CONTENT_TYPE_LIST => ['Audit.AzureActiveDirectory', 'Audit.Exchange', 'Audit.SharePoint', 'Audit.General'],
    CASB_CONTENT_TYPE_LIST => ['Audit.Exchange', 'Audit.SharePoint', 'Audit.General']
};

sub new
{
    my $class = shift;
    my %args = @_;
    # クラス変数として監査データを持つようにする
    $args{'_audit'} = ();
    my $this = $class->SUPER::new(%args);
    if (!$this) {
        return undef;
    }

    if ($this->_check_init()) {
        return undef;
    }

    return $this;
}

sub in24hours
{
    my $self = shift;
    my ($year, $mon, $mday, $hour, $min, $sec) = @_;

    my $offset = 60 * 60 * 24; # 24時間（秒）

    my $datetime = sprintf("%04d-%02d-%02d %02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec);
    my $epochTime = $self->SUPER::getEpoch($datetime);
    $epochTime += $offset;

    return $self->SUPER::getDateTime($epochTime);
}

sub checkExpire
{
    my $self = shift;

    # Office365は7日間しかログが取れない。
    # 7日以上前を指定されていた場合、今日から7日前をスタートとする
    my $start_time = shift;
    my $offset = 60 * 60 * 24 * 7; # 7日（秒）
    my $epochTime = time;
    $epochTime -= $offset;

    my ($year, $mon, $mday, $hour, $min, $sec) = $self->SUPER::getDateTime($epochTime);
    my $deadline = sprintf("%04d-%02d-%02dT%02d:%02d:%02d", $year, $mon, $mday, $hour, $min, $sec);

    if ( $start_time le $deadline ) {
        $self->{_info} = "$start_time is older date than $deadline.";
        return $deadline;
    }

    return $start_time;
}

sub _check_init
{
    my $self = shift;

    if (!defined($self->{'uid'}) || !$self->{'uid'}) {
        return 1;
    }
    if (!defined($self->{'seciossencryptedpassword;x-secret'}) || !$self->{'seciossencryptedpassword;x-secret'}) {
        return 1;
    }
    if (!defined($self->{'o'}) || !$self->{'o'}) {
        return 1;
    }
    return 0;
}

sub _judge_get_content
{
    my ($type, $is_casb) = @_;

    # CASB機能が有効化判定
    if($is_casb == 1){
        # 有効なら無条件で取得可能
        return 1;
    }

    # CASB機能が無効であれば、CASB用Content以外は取得可能
    foreach my $content_type (@{+CASB_CONTENT_TYPE_LIST}) {
        if ($content_type eq $type) {
            return 0;
        }
    }
    return 1;
}

sub _getAudit
{
    my $self = shift;
    my ($start_time, $type, $is_casb) = @_;
    my $directoryid = $self->{'o'};
    my $end_time = undef;

    # Office365は7日間しかログが取れない。
    # 7日以上前を指定されていた場合、今日から7日前をスタートとする
    $start_time = $self->checkExpire($start_time);
    if ($start_time =~ /^(\d{4})\-(\d{2})\-(\d{2})T(\d{2}):(\d{2}):(\d{2})/) {
        # Office365のDateTimeはUTCだが、Zが無いのでZと秒を削る
        my $year   = $1;
        my $mon    = $2;
        my $day    = $3;
        my $hour   = $4;
        my $min    = $5;
        my $sec    = $6;
        $start_time = "${year}-${mon}-${day}T${hour}:${min}";
        ($year, $mon, $day, $hour, $min, $sec) = $self->in24hours($year, $mon, $day, $hour, $min, $sec);
        $end_time = sprintf("%04d-%02d-%02dT%02d:%02d", $year, $mon, $day,$hour,$min);
    }

    my %params = (
        grant_type   => 'client_credentials',
        resource => RESOURCE,
        client_id => $self->{'uid'},
        client_secret => $self->{'seciossencryptedpassword;x-secret'},
    );
    # Authrization
    my $auth = $self->_authrization();
    unless ($auth) {
        $self->{_error} = 'Authentication of office 365 failed.';
        return;
    }
    # 有効なサブスクリプション確認
    my $active_subscriptions = $self->_getActiveSubscriptions($auth);
    unless ($active_subscriptions) {
        $self->{_error} = 'Failed to get active subscription list.';
        return;
    }

    # サブスクリプションの有効化
    foreach my $content_type (@{+CONTENT_TYPE_LIST}) {
        my $subscription_status = undef;
        my $isActive = undef;
        foreach my $subscription (@{$active_subscriptions}) {
            if($content_type eq $subscription->{'contentType'}){
                $isActive = 1;
                last;
            }
        }

        # CASB機能判定
        if(!_judge_get_content($content_type, $is_casb)){
            # 取得不可。サブスクリプションは無効にする
            $subscription_status = $self->_stopSubscription($auth, $content_type);
            unless ($subscription_status) {
                $self->{_error} = "Failed to stop subscription. Contet:${content_type}";
                return;
            }
        }

        # ログ取得可能。サブスクリプションが無効なら有効にする
        if(!$isActive){
            # サブスクリプションを有効にする
            $subscription_status = $self->_startSubscription($auth, $content_type);
            unless ($subscription_status) {
                $self->{_error} = 'Failed to start subscription.';
                return;
            }
            if($subscription_status->{'status'} ne 'enabled' ){
                $self->{_error} = "Failed to start subscription. ${content_type}:".$subscription_status->{'status'};
                return;
            }
        }
    }

    # コンテンツの利用可否確認
    foreach my $type (@{+CONTENT_TYPE_LIST}) {
        # コンテンツ一覧の検索
        my ($content_list, $next_page_uri) = $self->_getAuditContentList($auth, $type, $start_time, $end_time);
        unless ($content_list) {
            $self->{_info} = 'There are not yet available contents.';
            next;
        }
        # 取得したコンテンツ毎に詳細を取得・登録
        if (!$self->_setAduitData($auth, $content_list)){
            return;
        }
        # next_page_uriがundefになるまで_getAuditContentList を呼び続ける
        if($next_page_uri){
            if (!$self->_recursiveSetAuditContent($auth, $next_page_uri)){
                $self->{_error} = 'Failed to set content. mode:Next Page';
                return;
            }
        }
    }
    return 1;
}

sub _authrization
{
    my $self = shift;
    my $directoryid = $self->{'o'};

    my %params = (
        grant_type   => 'client_credentials',
        resource => RESOURCE,
        client_id => $self->{'uid'},
        client_secret => $self->{'seciossencryptedpassword;x-secret'},
    );
    # Authrization
    my $request = POST(AUTH_URL."/$directoryid/oauth2/token", [%params]);
    my $ua = LWP::UserAgent->new;
    my $response = $ua->request($request);
    unless ($response->is_success) {
        $self->{_error} = 'Failed to authorization: '.$response->status_line;
        return;
    }

    my $status  = $response->content;
    return decode_json($status);
}

sub _getActiveSubscriptions
{
    my $self = shift;
    my ($auth) = @_;
    my $directoryid = $self->{'o'};

    # 有効なサブスクリプション確認
    my $get_ua  = LWP::UserAgent->new;
    my $get_url = API_URL . '/api/v1.0/' . $directoryid . '/activity/feed/subscriptions/list';
    my $get_req = HTTP::Request->new(GET => $get_url);

    $get_req->header("Authorization" =>$auth->{token_type}.' '. $auth->{access_token});
    my $get_res = $get_ua->request($get_req);

    if ($get_res->is_success) {
        my $get_json = decode_json($get_res->content);
        return $get_json;
    } else {
        my $err_msg = $self->SUPER::error_message('office365', $get_res);
        $self->{_error} = 'Failed to get active subscription list: '.$err_msg;
        return;
    }
}

sub _startSubscription
{
    my $self = shift;
    my ($auth, $content_type) = @_;
    my $directoryid = $self->{'o'};

    # サブスクリプションの開始（変更もできる）
    my $request = POST(API_URL . '/api/v1.0/' . $directoryid . '/activity/feed/subscriptions/start?contentType='. $content_type . '&PublisherIdentifier=' . $directoryid);
    $request->header("Authorization" =>$auth->{token_type}.' '. $auth->{access_token});
    my $ua  = LWP::UserAgent->new;
    my $response = $ua->request($request);

    if ($response->is_success) {
        my $get_json = decode_json($response->content);
        return $get_json;
    } else {
        my $err_msg = $self->SUPER::error_message('office365', $response);
        $self->{_error} = 'Failed to start subscription' . $content_type . ': '.$err_msg;
        return;
    }
}

sub _stopSubscription
{
    my $self = shift;
    my ($auth, $content_type) = @_;
    my $directoryid = $self->{'o'};

    # サブスクリプションの停止
    my $request = POST(API_URL . '/api/v1.0/' . $directoryid . '/activity/feed/subscriptions/stop?contentType='. $content_type . '&PublisherIdentifier=' . $directoryid);
    $request->header("Authorization" =>$auth->{token_type}.' '. $auth->{access_token});
    my $ua  = LWP::UserAgent->new;
    my $response = $ua->request($request);

    if ($response->is_success) {
        return 1;
    } else {
        my $err_msg = $self->SUPER::error_message('office365', $response);
        $self->{_error} = 'Failed to stop subscription' . $content_type . ': '.$err_msg;
        return;
    }
}

sub _getAuditContentList
{
    my $self = shift;
    my ($auth, $content_type, $start_time, $end_time) = @_;
    my $directoryid = $self->{'o'};

    # コンテンツの一覧を取得
    my $get_ua  = LWP::UserAgent->new;
    my $get_url = API_URL . '/api/v1.0/' . $directoryid . '/activity/feed/subscriptions/content?contentType='. $content_type . '&PublisherIdentifier=' . $directoryid. '&startTime=' . $start_time. '&endTime=' . $end_time;
    my $get_req = HTTP::Request->new(GET => $get_url);

    $get_req->header("Authorization" =>$auth->{token_type}.' '. $auth->{access_token});
    my $get_res = $get_ua->request($get_req);

    if ($get_res->is_success) {
        my $next_page_uri = defined($get_res->headers->header('NextPageUri')) ? $get_res->headers->header('NextPageUri') : undef;
        my $get_json = decode_json($get_res->content);
        return ($get_json, $next_page_uri);
    } else {
        my $err_msg = $self->SUPER::error_message('office365', $get_res);
        $self->{_error} = 'Failed to get audit content' . $content_type . ': '.$err_msg;
        return;
    }
}

sub _getNextAuditContentList
{
    my $self = shift;
    my ($auth, $next_page_uri) = @_;
    my $directoryid = $self->{'o'};

    # 次ページのコンテンツの一覧を取得
    my $get_ua  = LWP::UserAgent->new;
    my $get_url = $next_page_uri. '?PublisherIdentifier=' . $directoryid;
    my $get_req = HTTP::Request->new(GET => $get_url);

    $get_req->header("Authorization" =>$auth->{token_type}.' '. $auth->{access_token});
    my $get_res = $get_ua->request($get_req);
    if ($get_res->is_success) {
        my $next_page_uri = defined($get_res->headers->header('NextPageUri')) ? $get_res->headers->header('NextPageUri') : undef;
        my $get_json = decode_json($get_res->content);
        return ($get_json, $next_page_uri);
    } else {
        my $err_msg = $self->SUPER::error_message('office365', $get_res);
        $self->{_error} = 'Failed to get audit content. mode: NextPage, status: '.$err_msg;
        return;
    }
}

sub _getAuditContent
{
    my $self = shift;
    my ($auth, $content_url) = @_;
    my $directoryid = $self->{'o'};
    my $get_url = $content_url. '?PublisherIdentifier=' . $directoryid;
    # コンテンツを取得
    my $get_ua  = LWP::UserAgent->new;
    my $get_req = HTTP::Request->new(GET => $get_url);

    $get_req->header("Authorization" =>$auth->{token_type}.' '. $auth->{access_token});
    my $get_res = $get_ua->request($get_req);

    if ($get_res->is_success) {
        my $get_json = decode_json($get_res->content);
        return $get_json;
    } else {
        my $err_msg = $self->SUPER::error_message('office365', $get_res);
        $self->{_error} = 'Failed to get content: '.$get_res->status_line. 'error code: '. $err_msg;
        return;
    }
}

sub _setData
{
    my $self = shift;
    my ($items) = @_;

    my $tmp_dir = $self->{'data_dir'};
    my @data;
    foreach my $row (@{$items}) {
        if (!defined $row->{'ClientIP'} || !$row->{'ClientIP'}) {
            next;
        }
        if (!defined $row->{'UserAgent'} && defined $row->{'ExtendedProperties'}) {
            for (my $i = 0; $i < scalar @{$row->{'ExtendedProperties'}}; $i++) {
                if ($row->{'ExtendedProperties'}->[$i]->{'Name'} eq "UserAgent") {
                    $row->{'UserAgent'} = $row->{'ExtendedProperties'}->[$i]->{'Value'};
                    last;
                }
            }
        }
        if (defined $row->{'UserAgent'} && $row->{'UserAgent'} eq 'MSWAC') {
            next;
        }
        $row->{'user'} = defined($row->{'UserId'}) ? $row->{'UserId'} : "";
        $row->{'double_check_value'} = $row->{'Id'};
        if($row->{'CreationTime'} !~ /^\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}Z/) {
            # Office365のDateTimeはUTCだが、Zが無いのでZが無ければ付与する（2015-06-29T20:03:19）
            $row->{'CreationTime'} = $row->{'CreationTime'}.'Z';
        }
        $row->{'@timestamp'} = $row->{'CreationTime'};
        push @{$self->{_audit}}, $row;
    }
    return;
}

sub _setAduitData
{
    my $self = shift;
    my ($auth, $content_list) = @_;

    # 取得したコンテンツ毎に詳細を取得・登録
    foreach my $content (@{$content_list}) {
        if(defined($content->{'contentUri'})){
            # コンテンツの詳細取得
            my $audit_content = $self->_getAuditContent($auth, $content->{'contentUri'});
            unless ($audit_content) {
                return;
            }
            # データの登録
            $self->_setData($audit_content);
        }else{
            $self->{_error} = "Failed to get content.";
            return;
        }
    }
    return 1;
}

sub _recursiveSetAuditContent
{
    # コンテンツを取得し登録する
    # コンテンツリストがHeaderでページングされるため、再帰処理
    my $self = shift;
    my ($auth, $audit_content_uri) = @_;

    # コンテンツの利用の可否を確認
    my ($content_list, $next_page_uri) = $self->_getNextAuditContentList($auth, $audit_content_uri);

    # コンテンツの取得と登録
    foreach my $content (@{$content_list}) {
        if(defined($content->{'contentUri'})){
            # コンテンツの詳細取得
            my $audit_content = $self->_getAuditContent($auth, $content->{'contentUri'});
            unless ($audit_content) {
                next;
            }
            # データの登録
            $self->_setData($audit_content);
        }else{
            $self->{_error} = "Failed to get content uri.";
            return;
        }
    }

    # 次ページがあれば処理続行
    if($next_page_uri){
        $self->_recursiveSetAuditContent($auth, $next_page_uri);
    }
    return 1;
}

1;