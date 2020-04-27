package Secioss::Audit::AWS;

use strict;
use warnings;
use Paws;
use Paws::Credential::Explicit;
use JSON;
use Data::Dumper;
use base qw(Secioss::Audit);


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
    if (!defined($self->{'seciossencryptedpassword'}) || !$self->{'seciossencryptedpassword'}) {
        return 1;
    }

    return 0;
}

sub _getAudit
{
    my $self = shift;
    my ($start_time, $type, $is_casb) = @_;

    my $result = 0;
    my $paws = Paws->new(config => {
        credentials => Paws::Credential::Explicit->new(
            access_key => $self->{'uid'},
            secret_key => $self->{'seciossencryptedpassword'}
        )
    });

    $self->{'StartTime'} = $self->SUPER::getEpoch($start_time);
    $self->{'EndTime'} = time() - 60;

    # リージョン事のイベントログを取得
    foreach my $region (
        "us-east-1",        # 米国東部（バージニア北部）
        "us-east-2",        # 米国東部 (オハイオ)
        "us-west-1",        # 米国西部 (北カリフォルニア)
        "us-west-2",        # 米国西部 (オレゴン)
        "ap-south-1",       # アジアパシフィック (ムンバイ)
        "ap-northeast-2",   # アジアパシフィック (ソウル)
        "ap-southeast-1",   # アジアパシフィック (シンガポール)
        "ap-southeast-2",   # アジアパシフィック (シドニー)
        "ap-northeast-1",   # アジアパシフィック (東京)
        "ap-northeast-3",   # アジアパシフィック (大阪: ローカル)
        "ca-central-1",     # カナダ (中部)
        "eu-central-1",     # 欧州 (フランクフルト)
        "eu-west-1",        # 欧州 (アイルランド)
        "eu-west-2",        # 欧州 (ロンドン)
        "eu-west-3",        # EU (パリ)
        "sa-east-1",        # 南米 (サンパウロ)
    ) {
        my $aws = $paws->service(
            'CloudTrail',
            MaxResults => 50,
            region => $region
        );

        my $response;
        eval {
            $response = $aws->LookupEvents(
                StartTime => int($self->{'StartTime'}),
                EndTime => int($self->{'EndTime'}),
                LookupAttributes => [
                    { AttributeKey => 'ReadOnly', AttributeValue => 'false' }
                ]
            );
        };
        if ($@) {
            $self->{_error} = "Failed to get aws audit[$region]: ".$@;
            return;
        }
        if (!$response) {
            $self->{_error} = "Failed to get aws audit[$region].";
            return;
        }
        $self->{'data'} = $self->_parseData($response->Events);
        $self->_setData($self->{'data'});

        while (defined $response->NextToken && $response->NextToken ne ''){
            # NextTokenがあれば再帰的に処理する

            $response = $self->_getNext($aws, $response);
            if(!defined $response){
                $self->{_error} = "Failed to get aws audit[$region]".($self->{_error} ? ': '.$self->{_error} : '.');
                return;
            }
        }

        # S3のReadOnlyログ取得
        $response = undef;
        eval {
            $response = $aws->LookupEvents(
                StartTime => int($self->{'StartTime'}),
                EndTime => int($self->{'EndTime'}),
                LookupAttributes => [
                    { AttributeKey => 'EventSource', AttributeValue => 's3.amazonaws.com' },
                    { AttributeKey => 'ReadOnly', AttributeValue => 'true' }
                ]
            );
        };
        if ($@) {
            $self->{_error} = "Failed to get aws audit[$region]: ".$@;
            return;
        }
        if (!$response) {
            $self->{_error} = "Failed to get aws audit[$region].";
            return;
        }
        $self->{'data'} = $self->_parseData($response->Events);
        $self->_setData($self->{'data'});

        while (defined $response->NextToken && $response->NextToken ne ''){
            # NextTokenがあれば再帰的に処理する

            $response = $self->_getNextS3($aws, $response);
            if(!defined $response){
                $self->{_error} = "Failed to get aws audit[$region]".($self->{_error} ? ': '.$self->{_error} : '.');
                return;
            }
        }

    }
    # Success
    return 1;
}

sub _getNext
{
    my $self = shift;
    my ($aws, $response) = @_;

    my $response_more;
    eval {
        $response_more = $aws->LookupEvents(
            StartTime => int($self->{'StartTime'}),
            EndTime => int($self->{'EndTime'}),
            LookupAttributes => [
                { AttributeKey => 'ReadOnly', AttributeValue => 'false' }
            ],
            NextToken => $response->NextToken
        );
    };
    if ($@) {
        $self->{_error} = $@;
        return;
    }
    if (!$response_more) {
        return;
    }
    $self->{'data'} = $self->_parseData($response_more->Events);
    $self->_setData($self->{'data'});

    no warnings 'recursion';
    return $response_more;
}

sub _getNextS3
{
    my $self = shift;
    my ($aws, $response) = @_;

    my $response_more;
    eval {
        $response_more = $aws->LookupEvents(
            StartTime => int($self->{'StartTime'}),
            EndTime => int($self->{'EndTime'}),
            LookupAttributes => [
                { AttributeKey => 'EventSource', AttributeValue => 's3.amazonaws.com' },
                { AttributeKey => 'ReadOnly', AttributeValue => 'true' }
            ],
            NextToken => $response->NextToken
        );
    };
    if ($@) {
        $self->{_error} = $@;
        return;
    }
    if (!$response_more) {
        return;
    }
    $self->{'data'} = $self->_parseData($response_more->Events);
    $self->_setData($self->{'data'});

    no warnings 'recursion';
    return $response_more;
}

sub _setData
{
    my $self = shift;
    my ($items) = @_;

    my $tmp_dir = $self->{'data_dir'};
    my @data;
    foreach my $row (@{$items}) {
        if (defined $row->{'userIdentity'}->{'type'} && $row->{'userIdentity'}->{'type'} eq 'AWSService') {
            $row->{'user'} = $row->{'userIdentity'}->{'invokedBy'};
        } else {
            my $user = $row->{'userIdentity'};
            if (defined($user->{'arn'})){
                $row->{'user'} = $user->{'arn'};
            }elsif (defined($user->{'userName'})){
                $row->{'user'} = $user->{'userName'};
            }elsif (defined($user->{'sessionContext'}) && defined($user->{'sessionContext'}->{'sessionIssuer'})){
                if (defined($user->{'sessionContext'}->{'sessionIssuer'}->{'arn'}) ){
                    $row->{'user'} = $user->{'sessionContext'}->{'sessionIssuer'}->{'arn'};
                }elsif(defined($user->{'sessionContext'}->{'sessionIssuer'}->{'userName'}) ){
                    $row->{'user'} = $user->{'sessionContext'}->{'sessionIssuer'}->{'userName'};
                }
            }
        }
        if(!defined $row->{'user'}){
            $row->{'user'} = '-';
        }
        $row->{'double_check_value'} = $row->{'eventID'};
        $row->{'@timestamp'} = $row->{'eventTime'};
        push @{$self->{_audit}}, $row;
    }
    return;
}

sub _parseData
{
    my $self = shift;
    my ($events) = @_;

    my @list = ();
    foreach my $event (@$events) {
        my $row = decode_json($event->CloudTrailEvent);
        push(@list, $row);
    }

    return \@list;
}

1;
