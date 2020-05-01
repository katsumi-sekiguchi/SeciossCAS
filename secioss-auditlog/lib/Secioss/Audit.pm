package Secioss::Audit;

use strict;
use warnings;
use Time::HiRes qw(gettimeofday);
use Time::Local qw(timelocal);
use Data::Dumper;

sub new
{
    my $class = shift;
    my (%args) = @_;

    my $self = {};
    bless $self, $class;

    $self->{_error} = '';
    $self->{_info} = '';

    foreach my $k (keys(%args)) {
        $self->{lc($k)} = $args{$k};
    }

    return $self;
}

sub getAudit
{
    my $self = shift;
    my ($tenant, $start_time, $type, $is_casb) = @_;

    return $self->_getAudit($tenant, $start_time, $type, $is_casb);
}

sub getDateTime
{
    my $self = shift;
    my ($epoch) = @_;

    my ($sec, $min, $hour, $mday, $mon, $year) = localtime($epoch);
    $year += 1900;
    $mon += 1;

    return ($year, $mon, $mday, $hour, $min, $sec);
}

sub getGMDateTime
{
    my $self = shift;
    my ($epoch) = @_;

    my ($sec, $min, $hour, $mday, $mon, $year) = gmtime($epoch);
    $year += 1900;
    $mon += 1;

    return ($year, $mon, $mday, $hour, $min, $sec);
}

sub getEpoch
{
    my $self = shift;
    my ($datetime) = @_;

    my $epoch = 0;
    if ($datetime =~ /^(\d{4})\-(\d{2})\-(\d{2}).(\d{2}):(\d{2}):(\d{2})/) {
        $epoch = timelocal($6, $5, $4, $3, $2-1, $1-1900);
    }

    return $epoch;
}

sub currentTime
{
    my $self = shift;
    my ($gmt, $time_diff) = @_;

    my ($epoch, $micro) = Time::HiRes::gettimeofday();
    my ($sec, $min, $hour, $mday, $mon, $year);
    if (defined($time_diff) && $time_diff) {
        $epoch += $time_diff * 3600;
    }
    if (defined($gmt) && $gmt) {
        ($year, $mon, $mday, $hour, $min, $sec) = $self->getGMDateTime($epoch);
    } else {
        ($year, $mon, $mday, $hour, $min, $sec) = $self->getDateTime($epoch);
    }

    return sprintf("%04d%02d%02d%02d%02d%02d%06d", $year, $mon, $mday, $hour, $min, $sec, $micro);
}

sub error_message {
    my $self = shift;
    my ($service, $response) = @_;

    my $msg = '';
    if ($response->content) {
        my $json;
        eval {
            $json = decode_json($response->content);
        };
        if (!$@) {
            if ($service eq 'box') {
                if (defined($json->{'message'})) {
                    $msg = $json->{'message'};
                }
            } elsif ($service eq 'dropbox') {
                if (defined($json->{'error_summary'})) {
                    $msg = $json->{'error_summary'};
                }
            } elsif ($service eq 'googleapps') {
                if (defined($json->{'error_description'})) {
                    $msg = $json->{'error_description'};
                }
            } elsif ($service eq 'lineworks') {
                if (defined($json->{'message'})) {
                    $msg = $json->{'message'};
                }
            } elsif ($service eq 'office365') {
                if (defined($json->{'error'}) && defined($json->{'error'}->{'message'})) {
                    $msg = $json->{'error'}->{'message'};
                }
            } elsif ($service eq 'salesforce') {
                if (defined($json->{'message'})) {
                    $msg = $json->{'message'};
                }
            }
        } else {
            $msg = $response->content;
        }
    }
    if (!$msg) {
        $msg = $response->status_line;
    }

    return $msg;
}

1;
