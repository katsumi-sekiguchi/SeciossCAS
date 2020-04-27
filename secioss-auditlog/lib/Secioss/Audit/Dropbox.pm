package Secioss::Audit::Dropbox;

use strict;
use warnings;
use Sys::Syslog;
use JSON;
use LWP::UserAgent;
use HTTP::Request::Common qw(POST);
use Digest::MD5 qw(md5_hex);
use Data::Dumper;
use base qw(Secioss::Audit);

use constant {
    API_URL => 'https://api.dropbox.com/2'
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

    if (!defined($self->{'seciossencryptedpassword;x-token'}) || !$self->{'seciossencryptedpassword;x-token'}) {
        return 1;
    }

    return 0;
}

sub _getAudit
{
    my $self = shift;
    my ($start_time, $type, $is_casb) = @_;

    my $param = '{"limit": 1000, "time": {"start_time": "'.$start_time.'"}}';
    my $req = HTTP::Request->new('POST', API_URL.'/team_log/get_events');
    $req->header('Content-Type' => "application/json");
    $req->header('Authorization' => "Bearer ".$self->{'seciossencryptedpassword;x-token'});
    $req->content($param);

    my $ua = LWP::UserAgent->new;
    my $res = $ua->request($req);
    unless ($res->is_success()) {
        my $err_msg = $self->SUPER::error_message('dropbox', $res);
        $self->{_error} = 'Failed to get dropbox audit: '.$err_msg;
        return;
    }
    my $json = decode_json($res->content);
    if (defined($json->{'error'}) && defined($json->{'error'}->{'.tag'}) || !defined($json->{'events'})) {
        $self->{_error} = 'Failed to get dropbox audit: '.$json->{'error'}->{'.tag'};
        return;
    }
    foreach my $d (@{ $json->{'events'} }) {
        push(@{$self->{'data'}} , $d);
    }

    return $self->_getNext($ua, $json);
}

sub _getNext
{
    my $self = shift;
    my ($ua, $json) = @_;

    if (!defined($json->{'has_more'}) || !$json->{'has_more'})  {
        if (scalar keys($self->{'data'})) {
            $self->_setData($self->{'data'});
            return 1;
        } else {
            return;
        }
    }

    my $param = '{"cursor": "'.$json->{'cursor'}.'"}';
    my $req = HTTP::Request->new('POST', API_URL.'/team_log/get_events/continue');
    $req->header('Content-Type' => "application/json");
    $req->header('Authorization' => "Bearer ".$self->{'seciossencryptedpassword;x-token'});
    $req->content($param);
    my $res = $ua->request($req);
    unless ($res->is_success()) {
        my $err_msg = $self->SUPER::error_message('dropbox', $res);
        $self->{_error} = 'Failed to get dropbox audit: '.$err_msg;
        return;
    }
    my $json_more = decode_json($res->content);
    if ((defined($json_more->{'error'}) && defined($json_more->{'error'}->{'.tag'})) || !defined($json_more->{'events'})) {
        $self->{_error} = 'Failed to get dropbox audit: '.$json_more->{'error'}->{'.tag'};
        return;
    }

    foreach my $d (@{ $json->{'entries'} }) {
        push(@{$self->{'data'}} , $d);
    }
    return $self->_getNext($ua, $json_more);
}

sub _setData
{
    my $self = shift;
    my ($items) = @_;
    foreach my $row (@{$items}) {
        if (!scalar keys($row)) {
            next;
        }
        my $tag = $row->{'actor'}->{'.tag'};
        if ($tag eq 'app') {
            $row->{'user'} = $row->{'actor'}->{'app'}->{'display_name'}.'('.$row->{'actor'}->{'app'}->{'app_id'}.')';
        } else {
            $row->{'user'} = $row->{'actor'}->{$tag}->{'display_name'}.'('.$row->{'actor'}->{$tag}->{'email'}.')';
        }
        $row->{'double_check_value'} = $row->{'timestamp'}.md5_hex(utf8::encode(JSON->new->encode($row)));
        $row->{'@timestamp'} = $row->{'timestamp'};
        push @{$self->{_audit}}, $row;
    }

    return;
}

1;
