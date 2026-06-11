use strict;
use warnings;
use lib 'lib';
use Test::More;
use Mail::DMARC::PurePerl;

use Test::File::ShareDir
  -share => { -dist => { 'Mail-DMARC' => 'share' } };

my $dmarc = Mail::DMARC::PurePerl->new();

# Mock DNS lookups
no warnings 'redefine';
my %dns_responses;
*Mail::DMARC::Base::has_dns_rr = sub {
    my ($self, $type, $domain) = @_;
    return $dns_responses{$domain}{$type} || 0;
};

# DMARCbis: discover_policy now uses tree_walk; mock it to read %dns_responses
*Mail::DMARC::PurePerl::tree_walk = sub {
    my ($self, $from_dom) = @_;
    $from_dom = lc $from_dom;
    # Try author domain first, then parent domain (one level up)
    my $rec = $dns_responses{"_dmarc.$from_dom"}{'TXT'};
    if ($rec) {
        return ($rec, $from_dom, $from_dom);
    }
    my @labels = split /\./, $from_dom;
    shift @labels;
    my $parent = join('.', @labels);
    if ($parent && $parent ne $from_dom) {
        $rec = $dns_responses{"_dmarc.$parent"}{'TXT'};
        if ($rec) {
            return ($rec, $parent, $parent);
        }
    }
    return (undef, undef, undef);
};

# Keep fetch_dmarc_record mock for any remaining callers
*Mail::DMARC::PurePerl::fetch_dmarc_record = sub {
    my ($self, $zone, $org_dom) = @_;
    my $rec = $dns_responses{"_dmarc.$zone"}{'TXT'};
    if ($rec) {
        return ([$rec], $zone);
    }
    if ($org_dom && $org_dom ne $zone) {
        return $self->fetch_dmarc_record($org_dom);
    }
    return ([], $zone);
};

subtest 'Basic Pass' => sub {
    $dmarc->init;
    $dmarc->header_from('example.com');
    $dmarc->dkim({ domain => 'example.com', result => 'pass', selector => 's1' });
    $dmarc->spf({ domain => 'example.com', scope => 'mfrom', result => 'pass' });
    
    %dns_responses = (
        'example.com' => { MX => 1 },
        '_dmarc.example.com' => { TXT => 'v=DMARC1; p=reject;' },
    );

    my $result = $dmarc->validate;
    is($result->result, 'pass', 'Result is pass');
    is($result->disposition, 'none', 'Disposition is none');
};

subtest 'SPF helo scope should not satisfy DMARC alignment' => sub {
    $dmarc->init;
    $dmarc->header_from('example.com');
    $dmarc->spf([
        {
            domain => 'other.com',
            scope  => 'mfrom',
            result => 'pass',   # mfrom pass but domain doesn't align
        },
        {
            domain => 'example.com',
            scope  => 'helo',
            result => 'pass',   # helo aligns but RFC 7489 §4.3.2 says only mfrom counts
        }
    ]);
    my $policy = Mail::DMARC::Policy->new(v => 'DMARC1', p => 'reject');
    $dmarc->{policy} = $policy;

    $dmarc->is_spf_aligned;

    is($dmarc->result->spf, 'fail', "helo-scoped SPF should not satisfy DMARC alignment");
};

subtest 'SPF should pass if at least one pass is aligned' => sub {
    $dmarc->init;
    $dmarc->header_from('example.com');
    $dmarc->spf([
        {
            domain => 'other.com',
            scope  => 'mfrom',
            result => 'pass',
        },
        {
            domain => 'example.com',
            scope  => 'mfrom',
            result => 'pass',
        }
    ]);
    my $policy = Mail::DMARC::Policy->new(v => 'DMARC1', p => 'reject');
    $dmarc->{policy} = $policy;

    $dmarc->is_spf_aligned;

    is($dmarc->result->spf, 'pass', "SPF should pass if at least one pass is aligned");
    is($dmarc->result->spf_align, 'strict', "SPF should be strictly aligned");
};

subtest 'SPF Fail, DKIM Pass' => sub {
    $dmarc->init;
    $dmarc->header_from('example.com');
    $dmarc->dkim({ domain => 'example.com', result => 'pass', selector => 's1' });
    $dmarc->spf({ domain => 'other.com', scope => 'mfrom', result => 'pass' }); # Unaligned
    
    %dns_responses = (
        'example.com' => { MX => 1 },
        '_dmarc.example.com' => { TXT => 'v=DMARC1; p=reject;' },
    );

    my $result = $dmarc->validate;
    is($result->result, 'pass', 'Result is pass (via DKIM)');
    is($result->disposition, 'none', 'Disposition is none');
};

subtest 'Both Fail, Policy Reject' => sub {
    $dmarc->init;
    $dmarc->header_from('example.com');
    $dmarc->dkim({ domain => 'other.com', result => 'pass', selector => 's1' }); # Unaligned
    $dmarc->spf({ domain => 'other.com', scope => 'mfrom', result => 'pass' }); # Unaligned
    
    %dns_responses = (
        'example.com' => { MX => 1 },
        '_dmarc.example.com' => { TXT => 'v=DMARC1; p=reject;' },
    );

    my $result = $dmarc->validate;
    is($result->result, 'fail', 'Result is fail');
    is($result->disposition, 'reject', 'Disposition is reject');
};

subtest 'Both Fail, Policy Quarantine' => sub {
    $dmarc->init;
    $dmarc->header_from('example.com');
    $dmarc->dkim({ domain => 'other.com', result => 'pass', selector => 's1' });
    $dmarc->spf({ domain => 'other.com', scope => 'mfrom', result => 'pass' });
    
    %dns_responses = (
        'example.com' => { MX => 1 },
        '_dmarc.example.com' => { TXT => 'v=DMARC1; p=quarantine;' },
    );

    my $result = $dmarc->validate;
    is($result->result, 'fail', 'Result is fail');
    is($result->disposition, 'quarantine', 'Disposition is quarantine');
};

subtest 'Subdomain Policy' => sub {
    $dmarc->init;
    $dmarc->header_from('sub.example.com');
    $dmarc->dkim({ domain => 'other.com', result => 'pass', selector => 's1' });
    $dmarc->spf({ domain => 'other.com', scope => 'mfrom', result => 'pass' });
    
    %dns_responses = (
        'sub.example.com' => { A => 1 },
        'example.com' => { NS => 1 },
        '_dmarc.example.com' => { TXT => 'v=DMARC1; p=none; sp=reject;' },
    );

    my $result = $dmarc->validate;
    is($result->result, 'fail', 'Result is fail');
    is($result->disposition, 'reject', 'Disposition is reject (via sp)');
};

subtest 'Relaxed Alignment' => sub {
    $dmarc->init;
    $dmarc->header_from('sub.example.com');
    $dmarc->dkim({ domain => 'example.com', result => 'pass', selector => 's1' });
    $dmarc->spf({ domain => 'other.example.com', scope => 'mfrom', result => 'pass' });
    
    %dns_responses = (
        'sub.example.com' => { A => 1 },
        'example.com' => { NS => 1 },
        '_dmarc.example.com' => { TXT => 'v=DMARC1; p=reject; adkim=r; aspf=r;' },
    );

    my $result = $dmarc->validate;
    is($result->result, 'pass', 'Result is pass (via relaxed alignment)');
    is($result->dkim_align, 'relaxed', 'DKIM alignment is relaxed');
    is($result->spf_align, 'relaxed', 'SPF alignment is relaxed');
};

subtest 'Strict Alignment (Fail)' => sub {
    $dmarc->init;
    $dmarc->header_from('sub.example.com');
    $dmarc->dkim({ domain => 'example.com', result => 'pass', selector => 's1' });
    $dmarc->spf({ domain => 'example.com', scope => 'mfrom', result => 'pass' });
    
    %dns_responses = (
        'sub.example.com' => { A => 1 },
        'example.com' => { NS => 1 },
        '_dmarc.example.com' => { TXT => 'v=DMARC1; p=reject; adkim=s; aspf=s;' },
    );

    my $result = $dmarc->validate;
    is($result->result, 'fail', 'Result is fail (strict alignment requested)');
};

subtest 'No Policy' => sub {
    $dmarc->init;
    $dmarc->header_from('example.com');
    
    %dns_responses = (
        'example.com' => { MX => 1 },
    );

    my $result = $dmarc->validate;
    is($result->result, 'none', 'Result is none when no policy found');
};

subtest 'PSL Exception (!www.ck)' => sub {
    $dmarc->init;
    
    # Mock PSL again for this test
    no warnings 'redefine';
    my $old_psl = \&Mail::DMARC::Base::get_public_suffix_list;
    *Mail::DMARC::Base::get_public_suffix_list = sub {
        return {
            'ck' => 1,
            '*.ck' => 1,
            '!www.ck' => 1,
        };
    };

    # Rule: *.ck is public suffix. foo.ck matches *.ck.
    # foo.ck is a public suffix (x=2 labels).
    # Org dom of bar.foo.ck is (x+1) = 3 labels -> bar.foo.ck.
    
    # Rule: !www.ck is exception. matches ck (x=1 label).
    # Org dom of bar.www.ck is (x+1) = 2 labels -> www.ck.
    
    is($dmarc->get_organizational_domain('bar.foo.ck'), 'bar.foo.ck', 'bar.foo.ck is org dom (foo.ck is public suffix)');
    is($dmarc->get_organizational_domain('bar.www.ck'), 'www.ck', 'www.ck is org dom (www.ck is NOT public suffix)');

    *Mail::DMARC::Base::get_public_suffix_list = $old_psl;
};

subtest 'Whitelisting' => sub {
    $dmarc->init;
    $dmarc->header_from('example.com');
    $dmarc->source_ip('1.2.3.4');
    
    # Create a temporary whitelist file
    my $white_file = 't/whitelist_test';
    open my $fh, '>', $white_file or die $!;
    print $fh "1.2.3.4 local_policy Whitelisted IP\n";
    close $fh;

    $dmarc->config->{smtp}{whitelist} = $white_file;
    delete $dmarc->{_whitelist}; # Clear cache

    # Both fail, but should be whitelisted to 'none'
    $dmarc->dkim({ domain => 'other.com', result => 'pass' });
    $dmarc->spf({ domain => 'other.com', scope => 'mfrom', result => 'pass' });
    
    %dns_responses = (
        'example.com' => { MX => 1 },
        '_dmarc.example.com' => { TXT => 'v=DMARC1; p=reject;' },
    );

    my $result = $dmarc->validate;
    is($result->result, 'fail', 'Result is still fail');
    is($result->disposition, 'none', 'Disposition is none due to whitelist');
    is($result->reason->[0]{type}, 'local_policy', 'Reason type is local_policy');
    is($result->reason->[0]{comment}, 'Whitelisted IP', 'Reason comment matches');

    unlink $white_file;
};

subtest 'External Reporting Verification' => sub {
    $dmarc->init;
    $dmarc->header_from('example.com');
    
    %dns_responses = (
        'example.com' => { MX => 1 },
        '_dmarc.example.com' => { TXT => 'v=DMARC1; p=none; rua=mailto:dmarc@other.com' },
        'example.com._report._dmarc.other.com' => { TXT => 'v=DMARC1' },
    );

    # We need to mock get_resolver->send for verify_external_reporting
    no warnings qw(redefine once);
    my $old_send = Net::DNS::Resolver->can('send');
    *Net::DNS::Resolver::send = sub {
        my ($self, $name, $type) = @_;
        # Very simple mock
        if ($dns_responses{$name} && $dns_responses{$name}{$type}) {
             # Return a mock object that has 'answer' method
             return bless { answer => [ bless { 
                 type => 'TXT', 
                 txtdata => $dns_responses{$name}{$type} 
             }, 'Net::DNS::RR::TXT' ] }, 'Net::DNS::Packet';
        }
        return;
    };
    *Net::DNS::RR::TXT::txtdata = sub { return $_[0]->{txtdata} };
    *Net::DNS::RR::TXT::type = sub { return 'TXT' };

    # Mock SUPER::save_aggregate to avoid DB errors
    *Mail::DMARC::save_aggregate = sub { return 1 };

    my $result = $dmarc->validate;
    my $rua = $result->published->rua;
    is($rua, 'mailto:dmarc@other.com', 'RUA is preserved if verified');

    my $res = $dmarc->save_aggregate();
    is($res, 1, 'save_aggregate succeeds if verified');

    # Test failure to verify
    delete $dns_responses{'example.com._report._dmarc.other.com'};
    $dmarc->init;
    $dmarc->header_from('example.com');
    $result = $dmarc->validate;
    
    $res = $dmarc->save_aggregate();
    is($res, undef, 'save_aggregate returns undef if NOT verified');

    *Net::DNS::Resolver::send = $old_send if $old_send;
};

done_testing();
