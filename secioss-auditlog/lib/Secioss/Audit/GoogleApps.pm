package Secioss::Audit::GoogleApps;

use strict;
use warnings;
use JSON;
use JSON::WebToken;
use LWP::UserAgent;
use HTML::Entities;
use HTTP::Request::Common qw(POST);
use Data::Dumper;
use base qw(Secioss::Audit);

use constant {
    AUTH_URL => 'https://accounts.google.com/o/oauth2/token',
    AUTH_SCOPE => 'https://www.googleapis.com/auth/admin.reports.audit.readonly',
    API_URL => 'https://www.googleapis.com/admin/reports/v1/activity'
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
    if (!defined($self->{'o'}) || !$self->{'o'}) {
        return 1;
    }
    if (!defined($self->{'mail'}) || !$self->{'mail'}) {
        return 1;
    }
    if (!defined($self->{'seciosscertificate'}) || !$self->{'seciosscertificate'}) {
        return 1;
    }

    return 0;
}

sub _getAudit
{
    my $self = shift;
    my ($start_time, $type, $is_casb) = @_;

    if (!defined($type)) {
        $type = 'login';
    }

    my $time = time;
    my $prm = $self->{'uid'} . "@" . $self->{'o'};

    my $jwt = JSON::WebToken->encode({
            iss => $self->{'mail'},
            scope => AUTH_SCOPE,
            aud => AUTH_URL,
            exp => $time + 3600,
            iat => $time,
            prn => $prm,
        },
        $self->{'seciosscertificate'},
        'RS256',
        {typ => 'JWT'}
    );

    # Now post it to google
    my $ua = LWP::UserAgent->new();
    my $response = $ua->post(AUTH_URL,
        {grant_type => encode_entities('urn:ietf:params:oauth:grant-type:jwt-bearer'),
        assertion => $jwt}
    );

    unless($response->is_success()) {
        my $err_msg = $self->SUPER::error_message('googleapps', $response);
        $self->{_error} = "Failed to get google audit: $err_msg";
        return;
    }

    my $data = decode_json($response->content);

    my $url = API_URL."/users/all/applications/$type?startTime=$start_time";
    my $req = HTTP::Request->new(GET => $url);
    $req->header("Content-Type" => "application/json");
    $req->header("Authorization" => "Bearer $data->{access_token}");
    my $res = $ua->request($req);

    if ($res->is_success) {
        my $json = decode_json($res->content);
        $self->_setData($json->{'items'});

        my $next_page_token = defined($json->{'nextPageToken'})? $json->{'nextPageToken'}: undef;
        if (defined($next_page_token)) {
            if(!$self->_getNextAudit($start_time, $type, $next_page_token)){
                $self->{_error} = 'Failed to set content. mode:Next Page';
                return;
            }
        } else {
            return 1;
        }
    } else {
        my $err_msg = $self->SUPER::error_message('googleapps', $res);
        $self->{_error} = "Failed to get google audit: $err_msg";
        return;
    }
    return 1;
}

sub _getNextAudit
{
    my $self = shift;
    my ($start_time, $type, $next_page_token) = @_;

    if (!defined($type)) {
        $type = 'login';
    }

    my $time = time;
    my $prm = $self->{'uid'} . "@" . $self->{'o'};

    my $jwt = JSON::WebToken->encode({
            iss => $self->{'mail'},
            scope => AUTH_SCOPE,
            aud => AUTH_URL,
            exp => $time + 3600,
            iat => $time,
            prn => $prm,
        },
        $self->{'seciosscertificate'},
        'RS256',
        {typ => 'JWT'}
    );

    # Now post it to google
    my $ua = LWP::UserAgent->new();
    my $response = $ua->post(AUTH_URL,
        {grant_type => encode_entities('urn:ietf:params:oauth:grant-type:jwt-bearer'),
        assertion => $jwt}
    );

    unless($response->is_success()) {
        my $err_msg = $self->SUPER::error_message('googleapps', $response);
        $self->{_error} = "Failed to get google audit: $err_msg";
        return;
    }

    my $data = decode_json($response->content);

    my $url = API_URL."/users/all/applications/$type?startTime=$start_time&pageToken=$next_page_token";
    my $req = HTTP::Request->new(GET => $url);
    $req->header("Content-Type" => "application/json");
    $req->header("Authorization" => "Bearer $data->{access_token}");
    my $res = $ua->request($req);

    if ($res->is_success) {
        my $json = decode_json($res->content);
        $self->_setData($json->{'items'});

        my $next_page_token = defined($json->{'nextPageToken'})? $json->{'nextPageToken'}: undef;
        if (defined($next_page_token)) {
            if(!$self->_getNextAudit($start_time, $type, $next_page_token)){
                $self->{_error} = 'Failed to set content. mode:Next Page';
                return;
            }
            # 正常
            return 1;
        } else {
            # 正常
            return 1;
        }
    } else {
        $self->{_error} = 'Failed to get google audit: '.$res->status_line;
        return;
    }
    # 異常
    return;
}


sub _setData
{
    my $self = shift;
    my ($items) = @_;

    my $tmp_dir = $self->{'data_dir'};
    my @data;
    foreach my $row (@{$items}) {
        if (!defined $row->{'ipAddress'} || !$row->{'ipAddress'}) {
            next;
        }
        $row->{'user'} = $row->{'actor'}->{'email'};
        $row->{'double_check_value'} = $row->{'etag'};
        $row->{'@timestamp'} = $row->{'id'}->{'time'};
        push @{$self->{_audit}}, $row;
    }
    return;
}

1;


