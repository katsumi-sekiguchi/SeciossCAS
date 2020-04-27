package Secioss::Audit::Box;

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
    API_URL => 'https://api.box.com/2.0'
};


sub new
{
    my $class = shift;
    my %args = @_;

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
    if (!defined($self->{'access_token'}) || !$self->{'access_token'}) {
        return 1;
    }

    return 0;
}

sub _getAudit
{
    my $self = shift;
    my ($start_time, $type, $is_casb) = @_;

    my $req = HTTP::Request->new('GET', API_URL.'/events?stream_type=admin_logs&limit=500&created_after='.$start_time);
    $req->header('Authorization' => 'Bearer '.$self->{'access_token'});
    my $ua = LWP::UserAgent->new;
    my $res = $ua->request($req);
    unless ($res->is_success()) {
        my $err_msg = $self->SUPER::error_message('box', $res);
        $self->{_error} = "Failed to get box audit: $err_msg";
        return;
    }
    my $json = decode_json($res->content);
    if (!defined($json->{'entries'})) {
        $self->{_error} = 'Failed to get box audit';
        return;
    }

    foreach my $d (@{ $json->{'entries'} }) {
         push(@{$self->{'data'}} , $d);
    }

    return $self->_getNext($ua, $json);
}

sub _getNext
{
    my $self = shift;
    my ($ua, $json) = @_;

    my $req = HTTP::Request->new('GET', API_URL.'/events?stream_type=admin_logs&limit=500&stream_position='.$json->{'next_stream_position'});
    $req->header('Authorization' => "Bearer ".$self->{'access_token'});
    my $res = $ua->request($req);
    unless ($res->is_success()) {
        my $err_msg = $self->SUPER::error_message('box', $res);
        $self->{_error} = "Failed to get box audit: $err_msg";
        return;
    }
    my $json_more = decode_json($res->content);
    if (!defined($json_more->{'entries'})) {
        $self->{_error} = 'Failed to get dropbox audit';
        return;
    }
    if (!$json_more->{'entries'}[0]) {
        if (scalar keys($self->{'data'})) {
            $self->_setData($self->{'data'});
            return 1;
        } else {
            return;
        }
    }

    foreach my $d (@{ $json_more->{'entries'} }) {
        push(@{$self->{'data'}} , $d);
    }

    no warnings 'recursion';
    return $self->_getNext($ua, $json_more);
}

sub _setData
{
    my $self = shift;
    my ($items) = @_;

    my $tmp_dir = $self->{'data_dir'};
    my @data;
    foreach my $row (@{$items}) {
        $row->{'user'} = $row->{'created_by'}->{'name'}.'('.$row->{'created_by'}->{'login'}.')';
        $row->{'double_check_value'} = $row->{'event_id'};
        $row->{'@timestamp'} = $row->{'created_at'};
        push @{$self->{_audit}}, $row;
    }

    return;
}

sub _tokenRefresh
{
    my $self = shift;

    my $ua = LWP::UserAgent->new;
    my %params = (
        'grant_type' => 'refresh_token',
        'refresh_token' => $self->{'seciossencryptedpassword;x-token'},
        'client_id' => $self->{'uid'},
        'client_secret' => $self->{'seciossencryptedpassword;x-secret'},
    );
    my $res = $ua->post($self->{'description;x-url-token'}, [%params]);
    unless ($res->is_success()) {
        $self->{_error} = 'Failed to get box access token: '.$res->status_line;
        return;
    }
    my $json = JSON->new->decode($res->content);
    if (!defined($json->{'refresh_token'}) || !defined($json->{'access_token'})) {
        $self->{_error} = 'Failed to get box access token';
        return;
    }
    $self->{'post_task'} = $json->{'refresh_token'};
    $self->{'access_token'} = $json->{'access_token'};

    return;
}

1;
