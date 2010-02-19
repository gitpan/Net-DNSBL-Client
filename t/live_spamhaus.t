use Test::More 0.82;
use Test::Deep;
use Net::DNSBL::Client;

plan skip_all => 'DNS unavailable; skipping tests' unless Net::DNS::Resolver->new->query('cpan.org');
plan tests => 1;

my $c = Net::DNSBL::Client->new();


$c->query_ip('127.0.0.2',
	[ {
		domain => 'zen.spamhaus.org',
		type   => 'match',
		data   => '127.0.0.2'
	},
	{
		domain => 'zen.spamhaus.org',
		type   => 'match',
		data   => '127.0.0.4'
	},
	{
		domain => 'zen.spamhaus.org',
		type   => 'match',
		data   => '127.0.0.10'
	},
	{
		domain => 'zen.spamhaus.org',
		type   => 'match',
		data   => '127.0.0.20'
	}
]);

my @expected = ({
		domain     => 'zen.spamhaus.org',
		userdata   => undef,
		hit        => 1,
		data       => '127.0.0.2',
		actual_hit => '127.0.0.2',
		type       => 'match'
	},
	{
		domain     => 'zen.spamhaus.org',
		userdata   => undef,
		hit        => 1,
		data       => '127.0.0.4',
		actual_hit => '127.0.0.4',
		type       => 'match'
	},
	{
		domain     => 'zen.spamhaus.org',
		userdata   => undef,
		hit        => 1,
		data       => '127.0.0.10',
		actual_hit => '127.0.0.10',
		type       => 'match'
	});

my $got = $c->get_answers();
cmp_deeply( $got, bag(@expected), "Got expected answers from spamhaus testpoint") || diag explain \@expected, $got;
