use Test::More 0.82;
use Test::Deep;
use Net::DNSBL::Client;

plan skip_all => 'DNS unavailable; skipping tests' unless Net::DNS::Resolver->new->query('cpan.org');
plan tests => 1;

my $c = Net::DNSBL::Client->new();

# http://www.dnswl.org/tech
$c->query_ip('127.0.0.2', [
	{
		domain => 'list.dnswl.org',
		type   => 'mask',
		data   => '127.0.255.255',
		userdata => 'Matches any dnswl.org category',
	},
]);

my @expected = (
	{
		domain => 'list.dnswl.org',
		userdata => 'Matches any dnswl.org category',
		hit => 1,
		data => '127.0.255.255',
		actual_hit => '127.0.10.0',
		type => 'mask'
	},
);
my $got = $c->get_answers();
cmp_deeply( $got, bag(@expected), "Got expected answers from dnswl testpoint") || diag explain \@expected, $got;
