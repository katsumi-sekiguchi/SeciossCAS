package Secioss::Audit::LineWorks;

use strict;
use warnings;
use Sys::Syslog;
use Net::LDAP;
use JSON;
use LWP::UserAgent;
use HTTP::Request::Common qw(POST);
use Data::Dumper;
use base qw(Secioss::Audit);

use constant {
    API_URL => 'https://jp1-audit.worksmobile.com/works/audit/log'
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

sub _check_init
{
    my $self = shift;

    if (!defined($self->{'uid'}) || !$self->{'uid'}) {
        return 1;
    }
    if (!defined($self->{'seciossencryptedpassword;x-token'}) || !$self->{'seciossencryptedpassword;x-token'}) {
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

sub _getAudit
{
    my $self = shift;
    my ($start_time, $audit_type, $is_casb) = @_;

    my $tenant_id = $self->{'uid'};
    my $domain_id = $self->{'o'};
    my $start_date = 0;

    if ($start_time =~ /^(\d{4})\-(\d{2})\-(\d{2})T(\d{2}):(\d{2}):(\d{2})/) {
        $start_date = $1.$2.$3;
    }

    my $end_date = $self->SUPER::currentTime(1, -1);
    if ($end_date =~ /^(\d{8})/) {
        $end_date = $1;
    }

    my $url = API_URL."/$audit_type/logs.json?apiId=downCsvLog&serviceId=audit&version=v1&_startDate=$start_date&_endDate=$end_date&_tenantId=$tenant_id&_domainId=$domain_id&rangeName=tenant&rangeValue=$tenant_id&language=ja-JP";

    my $req = HTTP::Request->new('GET', $url);
    $req->header('Authorization' => 'Bearer '.$self->{'seciossencryptedpassword;x-token'});
    $req->header('consumerKey' => $self->{'seciossencryptedpassword;x-secret'});
    my $ua = LWP::UserAgent->new;
    my $res = $ua->request($req);
    unless ($res->is_success()) {
        my $err_msg = $self->SUPER::error_message('lineworks', $res);
        $self->{_error} = 'Failed to get lineworks audit: '.$err_msg;
        return;
    }
    my $json = decode_json($res->content);
    if (!defined($json->{'Code'}) || $json->{'Code'} != 0 ) {
        $self->{_error} = 'Failed to get lineworks audit';
        return;
    }

    $self->_setData($audit_type, $json->{'items'});

    if ($json->{'lastKey'} eq ""){
        return 1;
    }

    # ページネーション処理
    my $lastKey = $json->{'lastKey'};
    while ($lastKey ne ""){
        $lastKey = $self->_getNext($ua, $lastKey, $url, $audit_type);
        if (!defined($lastKey)) {
            return;
        }
    }
    return 1;
}

sub _getNext
{
    my $self = shift;
    my ($ua, $lastKey, $url, $audit_type) = @_;

    my $req = HTTP::Request->new('GET', "$url&key=$lastKey&_key=$lastKey");
    $req->header('Authorization' => 'Bearer '.$self->{'seciossencryptedpassword;x-token'});
    $req->header('consumerKey' => $self->{'seciossencryptedpassword;x-secret'});
    my $res = $ua->request($req);
    unless ($res->is_success()) {
        my $err_msg = $self->SUPER::error_message('lineworks', $res);
        $self->{_error} = 'Failed to get lineworks audit for next page: '.$err_msg;
        return undef;
    }
    my $json_more = decode_json($res->content);
    if (!defined($json_more->{'Code'}) || $json_more->{'Code'} != 0 ) {
        $self->{_error} = 'Failed to get lineworks audit for next page';
        return undef;
    }

    $self->_setData($audit_type, $json_more->{'items'});
    if ($json_more->{'lastKey'} eq ""){
        # ページネーション終了
        return "";
    }
    return $json_more->{'lastKey'};
}

sub _formatDateTime
{
    my $self = shift;
    my ($datetime) = @_;

    # JSTからGMTへ変換
    my $sec_from_epoch = $self->SUPER::getEpoch($datetime) - (60 * 60 * 9);
    # 秒を日付と時刻に変換
    my ($year, $month, $mday, $hour, $min, $sec) = $self->SUPER::getDateTime( $sec_from_epoch );

    return sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ", $year, $month, $mday, $hour, $min, $sec);
}

sub _setData
{
    my $self = shift;
    my ($audit_type, $items) = @_;

    my $tmp_dir = $self->{'data_dir'};
    my $befor_key = "";
    my $counter = 0;
    foreach my $row (@{$items}) {
        # LINE WORKSはログ毎の一意なキーが無いため、カウンターを独自キーとする
        # row[0]はDate(JSTで取得される)
        my %hash = ();
        my $formatDate = $self->_formatDateTime(@$row[0]);
        my $double_check_value = $formatDate;
        if($formatDate eq $befor_key){
            $counter++;
            $double_check_value = $formatDate.'_'.$counter
        }else{
            $counter = 0;
        }
        $double_check_value =~ s/[\!\"\#\$\%\&\'\(\)\=\~\^\|\\\[\]\{\}\:\;\/\_\s]//g;
        $befor_key = $formatDate;

        # audit_type毎にカラムが違うのでフォーマット処理を行う
        if ($audit_type eq 'admin'){
            %hash = $self->_setAdmin($row);

        } elsif ($audit_type eq 'auth'){
            %hash = $self->_setAuth($row);

        } elsif ($audit_type eq 'home'){
            %hash = $self->_setHome($row);

        } elsif ($audit_type eq 'drive'){
            %hash = $self->_setDrive($row);

        } elsif ($audit_type eq 'calendar'){
            %hash = $self->_setCalendar($row);

        } elsif ($audit_type eq 'contact'){
            %hash = $self->_setContact($row);

        } elsif ($audit_type eq 'form'){
            %hash = $self->_setForm($row);

        } elsif ($audit_type eq 'share'){
            %hash = $self->_setShare($row);

        } elsif ($audit_type eq 'note'){
            %hash = $self->_setNote($row);

        } elsif ($audit_type eq 'received-mail'){
            %hash = $self->_setReceivedMail($row);

        } elsif ($audit_type eq 'message'){
            %hash = $self->_setMessage($row);

        } elsif ($audit_type eq 'sent-mail'){
            %hash = $self->_setSentMail($row);
        }

        $hash{'double_check_value'} = $double_check_value;
        $hash{'@timestamp'} = $formatDate;
        push @{$self->{_audit}}, \%hash;
    }
    return;
}

sub _setAdmin
{
    my $self = shift;
    my ($row) = @_;

    my %data;
    my $formatDate = $self->_formatDateTime(@$row[0]);
    # 必須
    $data{'user'} = @$row[6];
    # Authタイプ毎のフォーマット
    $data{'date'} = $formatDate;
    $data{'service'} = @$row[1];
    $data{'event_target'} = @$row[2];
    $data{'service_type'} = @$row[3];
    $data{'task'} = @$row[4];
    $data{'status'} = @$row[5];
    $data{'ip_address'} = @$row[7];

    return %data;
}

sub _setAuth
{
    my $self = shift;
    my ($row) = @_;

    my %data;
    my $formatDate = $self->_formatDateTime(@$row[0]);
    # 必須
    $data{'user'} = @$row[1];
    # Authタイプ毎のフォーマット
    $data{'date'} = $formatDate;
    $data{'description'} = @$row[2];
    $data{'service_type'} = @$row[3];
    $data{'ip_address'} = @$row[4];

    return %data;
}

sub _setHome
{
    my $self = shift;
    my ($row) = @_;

    my %data;
    my $formatDate = $self->_formatDateTime(@$row[0]);
    # 必須
    $data{'user'} = @$row[1];
    # Authタイプ毎のフォーマット
    $data{'date'} = $formatDate;
    $data{'service_type'} = @$row[2];
    $data{'task'} = @$row[3];
    $data{'subject'} = @$row[4];
    $data{'board_name'} = @$row[5];
    $data{'status'} = @$row[6];

    return %data;
}

sub _setDrive
{
    my $self = shift;
    my ($row) = @_;

    my %data;
    my $formatDate = $self->_formatDateTime(@$row[0]);
    # 必須
    $data{'user'} = @$row[1];
    # Authタイプ毎のフォーマット
    $data{'date'} = $formatDate;
    $data{'service_type'} = @$row[2];
    $data{'task'} = @$row[3];
    $data{'original'} = @$row[4];
    $data{'updates'} = @$row[5];
    $data{'status'} = @$row[6];

    return %data;
}

sub _setCalendar
{
    my $self = shift;
    my ($row) = @_;

    my %data;
    my $formatDate = $self->_formatDateTime(@$row[0]);
    # 必須
    $data{'user'} = @$row[1];
    # Authタイプ毎のフォーマット
    $data{'date'} = $formatDate;
    $data{'service_type'} = @$row[2];
    $data{'task'} = @$row[3];
    $data{'subject'} = @$row[4];
    $data{'calendar_id'} = @$row[5];
    $data{'status'} = @$row[6];

    return %data;
}

sub _setContact
{
    my $self = shift;
    my ($row) = @_;

    my %data;
    my $formatDate = $self->_formatDateTime(@$row[0]);
    # 必須
    $data{'user'} = @$row[1];
    # Authタイプ毎のフォーマット
    $data{'date'} = $formatDate;
    $data{'service_type'} = @$row[2];
    $data{'task'} = @$row[3];
    $data{'target'} = @$row[4];
    $data{'status'} = @$row[5];

    return %data;
}

sub _setForm
{
    my $self = shift;
    my ($row) = @_;

    my %data;
    my $formatDate = $self->_formatDateTime(@$row[0]);
    # 必須
    $data{'user'} = @$row[1];
    # Authタイプ毎のフォーマット
    $data{'date'} = $formatDate;
    $data{'service_type'} = @$row[2];
    $data{'task'} = @$row[3];
    $data{'form_title'} = @$row[4];
    $data{'status'} = @$row[5];

    return %data;
}

sub _setShare
{
    my $self = shift;
    my ($row) = @_;

    my %data;
    my $formatDate = $self->_formatDateTime(@$row[0]);
    # 必須
    $data{'user'} = @$row[1];
    # Authタイプ毎のフォーマット
    $data{'date'} = $formatDate;
    $data{'shared_by'} = @$row[1];
    $data{'participant'} = @$row[2];
    $data{'service_type'} = @$row[3];
    $data{'task'} = @$row[4];
    $data{'shared_with'} = @$row[5];

    return %data;
}

sub _setNote
{
    my $self = shift;
    my ($row) = @_;

    my %data;
    my $formatDate = $self->_formatDateTime(@$row[0]);
    # 必須
    $data{'user'} = @$row[1];
    # Authタイプ毎のフォーマット
    $data{'date'} = $formatDate;
    $data{'service_type'} = @$row[2];
    $data{'task'} = @$row[3];
    $data{'subject'} = @$row[4];
    $data{'board_name'} = @$row[5];
    $data{'team_groups'} = @$row[6];
    $data{'status'} = @$row[7];

    return %data;
}

sub _setReceivedMail
{
    my $self = shift;
    my ($row) = @_;

    my %data;
    my $formatDate = $self->_formatDateTime(@$row[0]);
    # 必須
    $data{'user'} = @$row[4];
    # Authタイプ毎のフォーマット
    $data{'received_time'} = $formatDate;
    $data{'reception_results'} = @$row[1];
    $data{'sent_server_ip'} = @$row[2];
    $data{'subject'} = @$row[3];
    $data{'sender'} = @$row[4];
    $data{'recipient'} = @$row[5];
    $data{'mail_size_bytes'} = @$row[6];

    return %data;
}

sub _setMessage
{
    my $self = shift;
    my ($row) = @_;

    my %data;
    my $formatDate = $self->_formatDateTime(@$row[0]);
    # 必須
    $data{'user'} = @$row[2];
    # Authタイプ毎のフォーマット
    $data{'date'} = $formatDate;
    $data{'sender'} = @$row[1];
    $data{'recipient'} = @$row[2];
    # $data{'message'} = @$row[3];

    return %data;
}

sub _setSentMail
{
    my $self = shift;
    my ($row) = @_;

    my %data;
    my $formatDate = $self->_formatDateTime(@$row[0]);
    # 必須
    $data{'user'} = @$row[2];
    # Authタイプ毎のフォーマット
    $data{'sent_time'} = $formatDate;
    $data{'subject'} = @$row[1];
    $data{'sender'} = @$row[2];
    $data{'recipient'} = @$row[3];
    $data{'status'} = @$row[4];
    $data{'attachment'} = @$row[5];
    $data{'mail_size_bytes'} = @$row[6];

    return %data;
}
1;
