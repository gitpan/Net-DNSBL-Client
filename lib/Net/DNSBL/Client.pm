package Net::DNSBL::Client;
use strict;
use warnings;
use 5.008;

use Carp;
use Net::DNS::Resolver;
use IO::Select;

our $VERSION = '0.100';

=head1 NAME

Net::DNSBL::Client - Client code for querying multible DNSBLs

=head1 SYNOPSIS

    use Net::DNSBL::Client;
    my $c = Net::DNSBL::Client->new({ timeout => 3 });

    $c->query_ip('127.0.0.2', [
        { domain => 'simple.dnsbl.tld' },
        { domain => 'masked.dnsbl.tld', type => 'mask', data => '127.0.0.255' }
    ]);

    # And later...
    my $answers = $c->get_answers();

=head1 METHODS

=head2 Class Methods

=over 4

=item new ( $args )

Returns a new Net::DNSBL::Client object.

$args is a hash reference and may contain the following key-value pairs:

=over 4

=item resolver

(optional) A Net::DNS::Resolver object.  If not provided, a new resolver will be created.

=item timeout

(optional) An integer number of seconds to use as the upper time limit
for the query.  If not provided, the default is 10 seconds.  If provided,
timeout must be a I<positive> integer.

=back

=back

=cut

sub new
{
	my ($class, $args) = @_;
	my $self = {
		resolver   => undef,
		timeout    => 10,
	};
	foreach my $possible_arg (keys(%$self)) {
		if( exists $args->{$possible_arg} ) {
			$self->{$possible_arg} = delete $args->{$possible_arg};
		}
	}
	if (scalar(%$args)) {
		croak("Unknown arguments to new: " .
		      join(', ', (sort { $a cmp $b } keys(%$args))));
	}

	# Timeout must be a positive integer
	if (($self->{timeout} !~ /^\d+$/) || $self->{timeout} <= 0) {
		croak("Timeout must be a positive integer");
	}

	$self->{resolver} = Net::DNS::Resolver->new() unless $self->{resolver};

	$self->{in_flight} = 0;
	$self->{early_exit} = 0;

	bless $self, $class;
	return $self;
}

=head2 Instance Methods

=over 4

=item get_resolver ( )

Returns the Net::DNS::Resolver object used for DNS queries.

=item get_timeout ( )

Returns the timeout in seconds for queries.

=item set_timeout ( $secs )

Sets the timeout in seconds for queries.

=item query_is_in_flight ( )

Returns non-zero if "query" has been called, but "get_answers" has not
yet been called.  Returns zero otherwise.

=item query_ip ( $ipaddr, $dnsbls [, $options])

Issues a set of DNS queries.  Note that the query_ip() method returns as
soon as the DNS queries have been issued.  It does I<not> wait for
DNS responses to come in.  Once query_ip() has been called, the
Net::DNSBL::Client object is said to have a query I<in flight>.  query_ip()
may not be called again while a query is in flight.

$ipaddr is the text representation of an IPv4 or IPv6 address.

$dnsbls is a reference to a list of DNSBL entries; each DNSBL entry
is a hash with the following members:

=over 4

=item domain

(required) The domain to query.  For example, I<zen.spamhaus.org>.

=item type

(optional) The type of DNSBL.  Possible values are I<normal>, meaning
that any returned A record indicates a hit, I<match>, meaning that
one of the returned A records must exactly match a given IP address, or
I<mask>, meaning that one of the returned A records must evaluate to non-zero
when bitwise-ANDed against a given IP address.  If omitted, type defaults
to I<normal>

=item data

(optional)  For the I<match> and I<mask> types, this data specifies the
required match or the bitwise-AND mask.  In the case of a I<mask> type,
the data can be something like "0.0.0.4", or an integer like "8".  In the
latter case, the integer I<n> must range from 1 to 255 and is equivalent
to 0.0.0.I<n>.

=item userdata

(optional) This element can be any scalar or reference that you like.
It is simply returned back unchanged in the list of hits.

=back

$options, if supplied, is a hash of options.  Currently, only one option
is defined:

=over 4

=item early_exit

If set to 1, querying will stop after the first positive result is
received, even if other DNSBLs are being queried.  Default is 0.

=back

=item get_answers ( )

This method may only be called while a query is in flight.  It waits
for DNS replies to come back and returns a reference to a list of I<hits>.
Once I<get_answers()> returns, a query is no longer in flight.

Each hit in the returned list is a hash reference containing the
following elements:

=over 4

=item domain

The domain of the DNSBL.

=item type

The type of the DNSBL (normal, match or mask).

=item data

The data supplied (for normal and mask types)

=item userdata

The userdata as supplied in the query_ip() call

=item actual_hit

The actual A record returned by the lookup that caused a hit.

=back

The hit may contain other elements not documented here; you should count
on only the elements documented above.

If no DNSBLs were hit, then a reference to a zero-element list is returned.

=back

=cut

sub get_resolver
{
	my ($self) = @_;
	return $self->{resolver};
}

sub get_timeout
{
	my ($self) = @_;
	return $self->{timeout};
}

sub set_timeout
{
	my ($self, $secs) = @_;
	if (($secs !~ /^\d+$/) || $secs <= 0) {
		croak("Timeout must be a positive integer");
	}
	$self->{timeout} = $secs;
	return $secs;
}

sub query_is_in_flight
{
	my ($self) = @_;
	return $self->{in_flight};
}

sub query_ip
{
	my ($self, $ipaddr, $dnsbls, $options) = @_;

	croak('Cannot issue new query while one is in flight') if $self->{in_flight};
	croak('First argument (ip address) is required')     unless $ipaddr;
	croak('Second argument (dnsbl list) is required')    unless $dnsbls;

	if ($options && exists($options->{early_exit})) {
		$self->{early_exit} = $options->{early_exit};
	} else {
		$self->{early_exit} = 0;
	}

	# Reverse the IP address in preparation for lookups
	my $revip = $self->_reverse_address($ipaddr);

	# Build a hash of domains to query.  The key is the domain;
	# value is an arrayref of type/data pairs
	$self->{domains} = $self->_build_domains($dnsbls);
	$self->_send_queries($revip);
}

sub get_answers
{
	my ($self) = @_;
	croak("Cannot call get_answers unless a query is in flight")
	    unless $self->{in_flight};

	my $ans = $self->_collect_results();
	$self->{in_flight} = 0;
	delete $self->{sel};
	delete $self->{sock_to_domain};
	delete $self->{domains};

	return $ans;
}

sub _build_domains
{
	my($self, $dnsbls) = @_;
	my $domains = {};

	foreach my $entry (@$dnsbls) {
		push(@{$domains->{$entry->{domain}}}, {
			domain   => $entry->{domain},
			type     => ($entry->{type} || 'normal'),
			data     => $entry->{data},
			userdata => $entry->{userdata},
			hit      => 0
		});
	}
	return $domains;
}

sub _send_queries
{
	my ($self, $revip) = @_;

	$self->{in_flight} = 1;
	$self->{sel} = IO::Select->new();
	$self->{sock_to_domain} = {};

	foreach my $domain (keys(%{$self->{domains}})) {
		my $sock = $self->{resolver}->bgsend("$revip.$domain", 'A');
		unless ($sock) {
			die $self->{resolver}->errorstring;
		}
		$self->{sock_to_domain}->{$sock} = $domain;
		$self->{sel}->add($sock);
	}
}

sub _collect_results
{
	my ($self) = @_;
	my $ans = [];

	my $terminate = time() + $self->{timeout};
	my $sel = $self->{sel};

	while(time() <= $terminate && $sel->count()) {
		my $expire = $terminate - time();
		$expire = 1 if ($expire < 1);
		my @ready = $sel->can_read($expire);

		return $ans unless scalar(@ready);

		foreach my $sock (@ready) {
			my $pack = $self->{resolver}->bgread($sock);
			my $domain = $self->{sock_to_domain}{$sock};
			$sel->remove($sock);
			undef($sock);
			next unless $pack;
			next if ($pack->header->rcode eq 'SERVFAIL' ||
				 $pack->header->rcode eq 'NXDOMAIN');
			$self->_process_reply($domain, $pack, $ans);
		}
		return $ans if ($self->{early_exit} && (scalar(@$ans) > 0));

	}
	return $ans;
}

sub _process_reply
{
	my ($self, $domain, $pack, $ans) = @_;

	my $entry = $self->{domains}->{$domain};

	foreach my $rr ($pack->answer) {
		next unless $rr->type eq 'A';
		foreach my $dnsbl (@$entry) {
			next if $dnsbl->{hit};
			if ($dnsbl->{type} eq 'normal') {
				$dnsbl->{hit} = 1;
			} elsif ($dnsbl->{type} eq 'match') {
				next unless $rr->address eq $dnsbl->{data};
				$dnsbl->{hit} = 1;
			} elsif ($dnsbl->{type} eq 'mask') {

				my @quads;
				# For mask, we can be given an IP mask like
				# a.b.c.d, or an integer n.  The latter case
				# is treated as 0.0.0.n.
				if ($dnsbl->{data} =~ /^\d+$/) {
					@quads = (0,0,0,$dnsbl->{data});
				} else {
					@quads = split(/\./,$dnsbl->{data});
				}

				my $mask = unpack('N',pack('C4', @quads));
				my $got  = unpack('N',pack('C4', split(/\./,$rr->address)));
				next unless ($got & $mask);

				$dnsbl->{hit} = 1;
			}

			if( $dnsbl->{hit} ) {
				$dnsbl->{actual_hit} = $rr->address;
				push(@$ans, $dnsbl);
			}
		}
	}
}

sub _reverse_address
{
	my ($self, $addr) = @_;

	# The following regex handles both regular IPv4 addresses
	# and IPv6-mapped IPV4 addresses (::ffff:a.b.c.d)
	if ($addr =~ /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) {
		return "$4.$3.$2.$1";
	}
	if ($addr =~ /:/) {
		$addr = $self->_expand_ipv6_address($addr);
		$addr =~ s/://g;
		return join('.', reverse(split(//, $addr)));
	}

	croak("Unrecognized IP address '$addr'");
}

sub _expand_ipv6_address
{
	my ($self, $addr) = @_;

	return '0000:0000:0000:0000:0000:0000:0000:0000' if ($addr eq '::');
	if ($addr =~ /::/) {
		# Do nothing if more than one pair of colons
		return $addr if ($addr =~ /::.*::/);

		# Make sure we don't begin or end with ::
		$addr = "0000$addr" if $addr =~ /^::/;
		$addr .= '0000' if $addr =~ /::$/;

		# Count number of colons
		my $colons = ($addr =~ tr/:/:/);
		if ($colons < 8) {
			my $missing = ':' . ('0000:' x (8 - $colons));
			$addr =~ s/::/$missing/;
		}
	}

	# Pad short fields
	return join(':', map { (length($_) < 4 ? ('0' x (4-length($_)) . $_) : $_) } (split(/:/, $addr)));
}

1;

__END__

=head1 DEPENDENCIES

L<Net::DNS::Resolver>, L<IO::Select>

=head1 AUTHOR

David Skoll <dfs@roaringpenguin.com>,
Dave O'Neill <dmo@roaringpenguin.com>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2010 Roaring Penguin Software

This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
