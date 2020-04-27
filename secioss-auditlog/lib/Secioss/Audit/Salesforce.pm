package Secioss::Audit::Salesforce;

use strict;
use warnings;
use Sys::Syslog;
use JSON;
use Text::CSV_XS;
use Time::HiRes;
use LWP::UserAgent;
use HTTP::Request::Common qw(POST);
use Data::Dumper;
use base qw(Secioss::Audit);

use constant {
    AUTH_URL => 'https://login.salesforce.com/services/oauth2/token',
    API_VER => '46.0'
};


# perl constructor
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

# 初期値確認処理
sub _check_init
{
    my $self = shift;

    if (!defined($self->{'uid'}) || !$self->{'uid'}) {
        return 1;
    }
    if (!defined($self->{'seciossencryptedpassword;x-secret'}) || !$self->{'seciossencryptedpassword;x-secret'}) {
        return 1;
    }
    if (!defined($self->{'seciossencryptedpassword'}) || !$self->{'seciossencryptedpassword'}) {
        return 1;
    }
    if (!defined($self->{'o'}) || !$self->{'o'}) {
        return 1;
    }
    if (!defined($self->{'mail'}) || !$self->{'mail'}) {
        return 1;
    }

    return 0;
}

# AuditLog取得処理
sub _getAudit
{
    my $self = shift;
    my ($start_time, $audit_type, $is_casb) = @_;

    # Its working but there might be better way to get the value from api
    my $api = $self->_getApiVer();
    if (!defined($api)) {
        return;
    }
    my $latest = pop $api;

    unless ($api && $latest->{'version'} >= API_VER) {
        $self->{_error} = "Failed to get useable API version: $latest->{'version'}, Require API version ${\API_VER}";
        return;
    }
    # Authorization
    my $auth = $self->_authorization();
    unless ($auth) {
        $self->{_error} = 'Authentication of salesforce failed.';
        return;
    }

    # Get EventLogFile
    my $domain = $self->{'o'};
    my $api_url = sprintf('https://%s.salesforce.com/services/data/v%s/', $domain, API_VER);
    my $soql = "SELECT+Id+,+EventType+,+LogFile+,+LogDate+,+LogFileFieldNames+FROM+EventLogFile+WHERE+LogDate+>=+$start_time+AND+Sequence+!=+0";
    my $url = sprintf('%squery?q=%s', $api_url, $soql);
    my $req = HTTP::Request->new(GET => $url);
    $req->header("Content-Type" => "application/json");
    $req->header("Authorization" => "Bearer $auth->{access_token}");
    my $ua = LWP::UserAgent->new;
    my $res = $ua->request($req);
    if ($res->is_success) {
        my $json = decode_json($res->content);
        if ($self->_setAuditData($auth, $json->{records})) {
            return 1;
        }
    } else {
        my $err_msg = $self->SUPER::error_message('salesforce', $res);
        $self->{_error} = 'Failed to get salesforce audit: '.$err_msg;
        return;
    }
}

sub _authorization
{
    my $self = shift;
    my $security_token = $self->{'seciossencryptedpassword;x-token'} || '';
    my %params = (
        grant_type => 'password',
        client_id => $self->{'uid'},
        client_secret => $self->{'seciossencryptedpassword;x-secret'},
        username => $self->{'mail'},
        password => "$self->{'seciossencryptedpassword'}$security_token"
    );

    my $request = POST(AUTH_URL, [%params]);
    my $ua = LWP::UserAgent->new;
    my $response = $ua->request($request);
    unless ($response->is_success) {
        my $err_msg = $self->SUPER::error_message('salesforce', $response);
        $self->{_error} = 'Failed to authorization: '.$err_msg;
        return;
    }

    my $status  = $response->content;
    return decode_json($status);
}

# 使用可能なAPI Versionを取得する
sub _getApiVer
{
    my $self = shift;
    my $domain = $self->{'o'};
    my $api_url = sprintf('https://%s.salesforce.com/services/data/', $domain);

    my $req = HTTP::Request->new(GET => $api_url);
    my $ua = LWP::UserAgent->new;
    my $response = $ua->request($req);

    unless ($response->is_success) {
        my $err_msg = $self->SUPER::error_message('salesforce', $response);
        $self->{_error} = 'Failed to get api version: '.$err_msg;
        return;
    }

    my $status  = $response->content;

    return decode_json($status);
}

# EventLogがエンドポイントで返却されるのでそれをリクエストする
sub _getEventLog
{
    my $self = shift;
    my ($auth, $logurl) = @_;
    my $domain = $self->{'o'};

    my $url = sprintf('https://%s.salesforce.com%s', $domain, $logurl);

    my $req = HTTP::Request->new(GET => $url);
    $req->header("Content-Type" => "application/json");
    $req->header("Authorization" => "Bearer $auth->{access_token}");

    my $ua = LWP::UserAgent->new;
    my $res = $ua->request($req);

    unless ($res->is_success) {
        my $err_msg = $self->SUPER::error_message('salesforce', $res);
        $self->{_error} = 'Failed to get salesforce logfile: '.$err_msg;
        return;
    }
    # CSV でEventLogが返却されるので注意
    my $status = $res->content;
    return $status;
}

sub _setAuditData
{
    my $self = shift;
    my ($auth, $content_list) = @_;
    my $domain = $self->{'o'};
    foreach my $content (@{$content_list}) {
        if(defined($content->{'LogFile'})) {
            my $logfile = $self->_getEventLog($auth, $content->{'LogFile'});
            unless ($logfile) {
                return;
            }
            $self->_setData($logfile);
        } else {
            $self->{_error} = "Failed to get LogFile.";
            return;
        }
    }

    return 1;
}

sub _setData
{
    my $self = shift;
    my ($logfile) = @_;
    my $flag_header = 1;

    my @headers;
    my $counter = 0;
    my $previous_key = "";
    my @data = (); # array of hashes
    my $csv = Text::CSV_XS->new ({
        binary    => 1,
        auto_diag => 1,
        sep_char  => ','
    });

    if (!$csv) {
        die "Can't use CSV_XS: ".Text::CSV_XS->error_diag()."\n";
    }

    open my $fh, "<", \$logfile;
    while (my $fields = $csv->getline ($fh)) {
        my @coloumns =();
        my %hash =();
        if($flag_header == 1){
            foreach(@{ $fields }) {
                    my $new = $_;
                    push(@headers, $new);
                }
        } else {
            foreach(@{ $fields }) {
                my $new = $_;
                push(@coloumns, $new);
            }

            for my $iteration (0..$#coloumns){
                my $key  = $headers[$iteration];
                my $data = $coloumns[$iteration];
                $hash{$key} = $data;
            }
        }
        if($flag_header > 1 && !(defined($hash{'ENTITY_NAME'}) && $hash{'ENTITY_NAME'} eq 'EventLogFile')){
            my $double_check_value = $hash{'REQUEST_ID'};
            if ($double_check_value eq $previous_key) {
                $counter ++;
                $double_check_value = $double_check_value.'_'.$counter;
            } else {
                $counter = 0;
            }
            $previous_key = $double_check_value;
            $hash{'user'} = exists($hash{'USER_NAME'}) ? $hash{'USER_NAME'} : $hash{'USER_ID'};
            $hash{'double_check_value'} = $double_check_value;
            $hash{'@timestamp'} = $hash{'TIMESTAMP_DERIVED'};
            push @{$self->{_audit}}, \%hash;
        }
        $flag_header +=1;
    }
    close $fh;
}

1;