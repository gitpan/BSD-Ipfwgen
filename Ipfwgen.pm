
#
# BSD::Ipfwgen
#
# Copyright (C) 1998, David Muir Sharnoff.   All rights reserved.
# License hearby granted for anyone to use this module at their own risk.   
# Please feed useful changes back to muir@idiom.com.
#


#
# For each of the sets (recv, xmit, network, protocol), build
# the ruleset like:
#
# =skiprule all from any to any recv interface
# =skipto end-section all from any to any
# do stuff
# =label end-section
#

package BSD::Ipfwgen;

my $ifconfig = "/sbin/ifconfig";
my $netstat = "/usr/bin/netstat";
my $ipfw = "/sbin/ipfw";

use vars qw($VERSION);
$VERSION = 1.0;

require Exporter;

@ISA = qw(Exporter);
@EXPORT = qw(
	outside leaf 
	us not_us consolidate symmetric
	count_by_interface count_by_address 
	count_by_udp count_by_tcp 
	no_looping no_spoofing_us no_spoofing_by_us no_leaf_spoofing
	generate 
	drop_unwanted 
	tcp_from_rules udp_from_rules 
	tcp_to_rules udp_to_rules 
	from_net_rules to_net_rules 
	to_me_rules from_me_rules
	not_to_me_rules not_from_me_rules
	in_interface_rules out_interface_rules
	);

my @outside;
my @leaf;
my @us;
my @not_us;
my @symmetric;
my @interesting;
my %consolidate;

use Carp;

# BEGIN { use IO::Handle; open(DEBUG, ">&STDERR"); autoflush DEBUG 1; }
BEGIN { open(DEBUG, ">/dev/null"); };


sub watch
{
	my (@net) = @_;
	for my $net (@net) {
		print DEBUG "watch $net\n";
		confess unless defined $net;
		my ($network, $bits) = get_netmask($net);
		$network =~ /^(\d+\.\d+\.\d+)\.(\d+)$/
			or die "could not grok netnum $network";
		$watch{$1} = 1;
	}
}

# interfaces
sub outside { push(@outside, @_); }
sub leaf { push(@leaf, @_); };

# networks
sub interesting { push(@interesting, @_); watch(@_); }
sub us { push(@us, @_); watch(@_); };
sub not_us { push(@not_us, @_); watch(@_); };
sub symmetric { push(@symmetric, @_); watch(@_); };

sub get_netmask
{
	my ($net, $mask) = @_;
	$mask = '' unless defined $mask;
	if ($net =~ m,^(\d+\.\d+\.\d+\.\d+):(\d+\.\d+\.\d+\.\d+)$,) {
		#XXX
	} elsif ($net =~ m,^(\d+\.\d+\.\d+\.\d+)/(\d+)$,) {
		return ($1, $2);
	} elsif (($net =~ m,^\d+\.\d+\.\d+\.\d+$,) &&
		($mask =~ m,0x[a-z0-9]+,i)) {
		use integer;
		my $nm = hex($mask);
		my $bits = 32;
		while ($nm & 0x1 == 0 && $bits > 0) {
			$bits--;
			$nm >>= 1;
		}
		return ($net, $bits);
	} elsif ($net =~ /^\d+\.\d+\.\d+\.\d+$/ && ! $mask) {
		return ($net, 32);
	} elsif ($net =~ /^\d+\.\d+\.\d+$/ && ! $mask) {
		return ("$net.0", 24);
	} elsif ($net =~ /^\d+\.\d+$/ && ! $mask) {
		return ("$net.0.0", 16);
	} elsif ($net =~ /^\d+$/ && ! $mask) {
		return ("$net.0.0.0", 8);
	} elsif ($net =~ m,^(\d+\.\d+\.\d+)/(\d+)$,) {
		return ("$1.0", $2);
	} elsif ($net eq 'default') {
		return ("0.0.0.0", 0);
	} else {
		die "could not parse $net $mask";
	}
}

sub consolidate 
{
	my (@consolidate) = @_;
	for my $c (@consolidate) {
		print DEBUG "consolidate $c\n";
		my ($network, $bits) = get_netmask($c);
		die "can only consolidate class Cs or smaller" 
			if $bits < 24;
		$network =~ /^(\d+\.\d+\.\d+)\.(\d+)$/
			or die "could not grok netnum $network";
		my ($base, $ext) = ($1, $2);
		my $count = 2**(32-$bits);
		while ($count > 0) {
			$consolidate{"$base.$ext"} = $c;
			print DEBUG "consolidate{$base.$ext} = $c\n";
			$ext++;
			$count--;
		}
	}
}

my %interfaces;

sub get_direct_nets
{ 
	my ($if) = @_;

	my @n;
	for my $i (0..$#{$interface->{$if}->{'IP'}}) {
		my $ip = $interface->{$if}->{'IP'}->[$i];
		if ($interface->{$if}->{'TYPE'} eq 'BROADCAST') {
			my ($base, $bits) = get_netmask(
				$ip, $interface->{$if}->{'NETMASK'}->[$i]);
			push(@n, "$base/$bits");
		} else {
			push(@n, $ip);
		}
	}
	return (); 
}

sub interface
{
	my ($ifname, $ifaddr, $type, $flags, $dataname, $data) = @_;
	if (exists $interfaces{$ifname}) {
		die "$ifname not $type!" 
			unless $interfaces{$ifname}->{'TYPE'} eq $type;
	} else {
		$interfaces{$ifname} = { 
			'IP' => [], 
			'IPindex' => {},
			'ROUTES' => {},
		};
		$interfaces{$ifname}->{$dataname} = []
			if $dataname;
		$interfaces{$ifname}->{'TYPE'} = $type;
	}
	if ($consolidate{$ifaddr}) {
		$ifaddr = $consolidate{$ifaddr};
		return if exists ${$interfaces{$ifname}->{'IPindex'}}{$ifaddr};
	}
	push(@{$interfaces{$ifname}->{'IP'}}, $ifaddr);
	push(@{$interfaces{$ifname}->{$dataname}}, $data)
		if $dataname;
	$interfaces{$ifname}->{'IPindex'}->{$ifaddr} = $data;
}

sub get_interfaces
{
	open(IFCONFIG, "$ifconfig -a|") or die "open $ifconfig|: $!";
	my $interface;
	my $flags;
	while (<IFCONFIG>) {
		if (/^([a-z]+\d+): flags=[\da-f]+\<([A-Z0-9,]+)\> mtu \d+/) {
			$ifnam = $1;
			$flags = $2;
		} elsif (/^\s+inet (\S+) netmask (\S+) broadcast (\S+)\s*$/) {
			interface($ifnam, $1, 'BROADCAST', $flags, 'NETMASK', $2);
			next;
		} elsif (/^\s+inet (\S+) --\> (\S+)/) {
			interface($ifnam, $1, 'POINTTOPOINT', $flags, 'PEER', $2);
		} elsif (/^\s+inet (\S+) netmask (\S+)\s*$/) {
			interface($ifnam, $1, 'LOOPBACK', $flags);
		} elsif (/^\s+ether\s+\S+/) {
			# ignore
		} else {
			warn "did not understand $ifconfig -a output: $_";
		}
	}
	close(IFCONFIG);
}

my %track_net;
my %track_interface;

sub c_addr
{
	my ($dest) = @_;
	my ($base, $mask) = get_netmask($dest);
	($base =~ m/^(\d+\.\d+\.\d+)\.\d+$/)
		or die "parse route dest $dest ($base)";
	return $1;
}

sub route 
{
	my ($dest, $gate, $interface) = @_;

	return unless (exists $track_net{c_addr($dest)}
		|| exists $track_interface{$interface});

}

sub get_direct_interface
{
	my ($net) = @_;

	return $interface;
}

# XXX
sub get_nets { return ()}

sub get_routes 
{
	for my $net (@us, @symmetric, @interesting, @not_us) {
		my ($base, $mask) = get_netmask($net);
		if ($mask >= 24) {
			$base =~ m/^(\d+\.\d+\.\d+)\.\d+$/
				or die "parse dest $net ($base)";
			$track_net{$1} = $net;
		} else {
			die if $mask < 16;
			$base =~ /^(\d+\.\d+)\.(\d+)\.\d+$/
				or die "parse dest $net ($base)";
			my ($netbase, $ext) = ($1, $2);
			my $count = 2**(24-$mask);
			print DEBUG "Count: $count on $net ($mask)\n";
			while ($count > 0) {
				$track_net{"$netbase.$ext.0"} = $net;
				print DEBUG "track_net{$netbase.$ext.0}\n";
				$ext++;
				$count--;
			}
		}
	}
	@track_interface{@leaf} = @leaf;

	open(NETSTAT, "$netstat -rn|") or die "open $netstat -rn|: $!";
	while (<NETSTAT>) {
		last if /^Internet/;
	}
	my ($dest, $gate, $flags, $refs, $use, $interface, $expire);
	while (<NETSTAT>) {
		last if /^$/;
		next if /^Destination/;
		($dest, $gate, $flags, $refs, $use, $interface, $expire) 
			= split(' ',$_);
		next unless $interface;
		unless ($interface =~ /^[a-z]+\d+/) {
			warn "Could not understat $netstat -rn: $_";
			next;
		}
		next unless $gate =~ /^[\d\.]+$/;
		route($dest, $gate, $interface);
	}
	close(NETSTAT);
}

#
# per-interface recv
# per-interface xmit
# per-protocol
# per-network/host
#
my %in_rules;
my %out_rules;
my %udp_from_rules;
my %tcp_from_rules;
my %udp_to_rules;
my %tcp_to_rules;
my %from_net_rules;
my %to_net_rules;
my $begun = 0;

my @from_me_rules;
my @to_me_rules;

my @not_from_me_rules;
my @not_to_me_rules;

my %count_in;
my %count_out;
my %count_udp_from;
my %count_tcp_from;
my %count_udp_to;
my %count_tcp_to;
my @count;

sub must_exist
{
	my ($desc, $ar) = @_;

	my @n;
	for my $i (@$ar) {
		if (exists $interfaces{$i}) {
			push(@n, $i);
		} else {
			warn "no $desc interface $i!";
		}
	}
	@$ar = @n;
}

sub begin
{
	get_interfaces();
	
	must_exist('leaf', \@leaf);
	must_exist('outside', \@outside);

	get_routes();

	$begun = 1;
}

sub count_by_interface
{
	begin() unless $begun;
	for $i (sort keys %interfaces) {
		push(@{$count_in{$i}}, 
			"count all from any to any in via $i # cbi");
		push(@{$count_out{$i}}, 
			"count all from any to any out via $i # cbi");
	}
}

sub count_by_tcp
{
	my (@protos) = @_;
	begin() unless $begun;
	for $o (@outside) {
		for $p (@protos) {
			push(@{$count_tcp_from{$p}},
				"count tcp from any $p to any in via $o # cbt",
				"count tcp from any $p to any out via $o");
			push(@{$count_tcp_to{$p}},
				"count tcp from any to any $p in via $o # cbt",
				"count tcp from any to any $p out via $o");
		}
	}
	if (! @outside) {
		for $p (@protos) {
			push(@{$count_tcp_from{$p}},
				"count tcp from any $p to any # cbt");
		}
	}
}

sub count_by_udp
{
	my (@protos) = @_;
	begin() unless $begun;
	for $p (@protos) {
		for $o (@outside) {
			push(@{$count_udp_from{$p}},
				"count udp from any $p to any in via $o # cbu",
				"count udp from any $p to any out via $o");
			push(@{$count_udp_to{$p}},
				"count udp from any to any $p in via $o # cbu",
				"count udp from any to any $p out via $o");
		}
		if (! @outside) {
			push(@{$count_udp_from{$p}},
				"count udp from any $p to any # cbu");
		}
	}
}

sub count_by_address
{
	my (@addr) = @_;
	begin() unless $begun;
	for $a (@addr) {
		push(@count,
			"count all from $a to any # cba",
			"count all from any to $a");
	}
}

sub no_looping
{
	begin() unless $begun;
	for my $o (@outside) {
		push(@{$out_rules{$o}},
			"deny all from any to =US out xmit $o # nlo");
	}

	for my $i (sort keys %interfaces) {
		if ($interfaces{$i}->{'TYPE'} eq 'POINTTOPOINT') {
			push(@{$out_rules{$i}},
				"deny tcp from any to any out recv $i xmit $i # nlnb",
				"deny udp from any to any out recv $i xmit $i # nlnb");
		}
	}

	for my $i (@leaf) {
		next unless $interfaces{$i}->{'TYPE'} eq 'BROADCAST';
		for my $r (get_nets{$i}) {
			push(@{$out_rules{$i}},
				"deny all from $r to any out recv $i xmit $i # nlb");
		}
	}
	# XXX @symmetric
}

sub drop_unwanted
{
	my (@unwanted) = @_;
	begin() unless $begun;
	for my $u (@unwanted) {
		push(@{$from_net_rules{$u}},
			"=deny all from $u to any # unwanted");
	}
}

sub no_spoofing_by_us
{
	#
	# We can't pretened to be others
	#
	begin() unless $begun;
	for my $o (@outside) {
		push(@{$out_rules{$o}},
			"=skiprule all from =US to any out xmit $o # ns-o",
			"=deny all from any to any out via $o");
	}
}

sub no_spoofing_us
{
	begin() unless $begun;

	# people outside can't spoof people inside
	for my $o (@outside) {
		push(@{$in_rules{$o}},
			"deny all from =US to any in recv $o # ns-o");
	}

	# traffic from locally attached networks must come in via that
	# network
	for my $i (sort keys %interfaces) {
		print DEBUG "making sure traffic from $i is really from $i\n";
		# XXX this might give duplication
		for my $net (get_direct_nets($i)) {
			print "DEBUG r=$net\n";
			push(@{$from_net_rules{$net}},
				"=skiprule all from $net to any in via $i # ns-la",
				"=deny all from $net to any");
		}
	}
}

sub no_leaf_spoofing
{
	begin() unless $begun;

	# people who aren't in the leaf can't spoof the leaf
	# people who are in the leaf can't pretend otherwise
	for my $i (@leaf) {
		for my $r (get_nets($i)) {
			push(@{$from_net_rules{$r}},
				"=skiprule all from $r to any in via $i # ns-l",
				"=deny all from $r to any");
			push(@{$in_from{$i}},
				"=skipto okay-outspoof-$i all from $r to any in via $i # ns-l");
		}
		push(@{$in_from{$i}},
			"=deny all from any to any in via $i # ns-l",
			"=label okay-outspoof-$i");
	}
}

sub clean_rules
{
	my ($rules) = @_;
	my @r = split("\n", $rules);
	for my $r (@r) {
		$r =~ s/^\s+//;
	}	
	return (@r);
}

sub in_interface_rules { my($in, $rules) = @_; push(@{$in_rules{$in}}, clean_rules($rules)); }
sub out_interface_rules { my($in, $rules) = @_; push(@{$out_rules{$in}}, clean_rules($rules)); }

sub udp_from_rules { my($port, $rules) = @_; push(@{$udp_from_rules{$port}}, clean_rules($rules)); }
sub tcp_from_rules { my($port, $rules) = @_; push(@{$tcp_from_rules{$port}}, clean_rules($rules)); }
sub udp_to_rules { my($port, $rules) = @_; push(@{$udp_to_rules{$port}}, clean_rules($rules)); }
sub tcp_to_rules { my($port, $rules) = @_; push(@{$tcp_to_rules{$port}}, clean_rules($rules)); }

sub from_net_rules { my($net, $rules) = @_; push(@{$from_net_rules{$net}}, clean_rules($rules)); }
sub to_net_rules { my($net, $rules) = @_; push(@{$to_net_rules{$net}}, clean_rules($rules)); }

sub from_me_rules { my($rules) = @_; push(@from_me_rules, clean_rules($rules)); }
sub to_me_rules { my($rules) = @_; push(@to_me_rules, clean_rules($rules)); }
sub not_from_me_rules { my($rules) = @_; push(@not_from_me_rules, clean_rules($rules)); }
sub not_to_me_rules { my($rules) = @_; push(@not_to_me_rules, clean_rules($rules)); }

#sub modload
#	modload /lkm/ipfw_mod.o
#	XXX
#

my $genlabel = "genlabel00000";
my @rules;

sub gensect
{
	my ($required, $negative, $many, %set) = @_;
	my $passlabel;
	if ($required) {
		push(@rules,
			"=skiprule $required # gs-h ",
			"=skipto $genlabel all from any to any");
		$passlabel = $genlabel++;
	}
	for my $k (sort keys %set) {
		my $control = $many;
		$control =~ s/=KEY/$k/g;

		my @s = @{$set{$k}};
		my $cando = 1;
		if (@s < 4 && $control =~ /\</) {
			my $re = $control;
			$re =~ s/<(.*?)>/<\Q$1\E>/g;
			$re =~ s/>.*?</.+/g;
			$re =~ s/^.*?<//;
			$re =~ s/>[^<]*$//;
			print DEBUG "control($control) => '$re'\n";
			for my $s (@s) {
				next if $s =~ /$re/;
				print DEBUG "NO MATCH on $s\n";
				$cando = 0;
				last;
			}
			if ($cando) {
				push(@rules, @{$set{$k}});
				next;
			}
		} 

		$control =~ s/[<>]//g;

		if ($negative) {
			push(@rules, 
				"=skipto $genlabel $control # $many",
				@{$set{$k}},
				"=label $genlabel");
		} else {
			push(@rules, 
				"=skiprule $control # $many",
				"=skipto $genlabel all from any to any",
				@{$set{$k}},
				"=label $genlabel");
		}
		$genlabel++;
	}
	push(@rules, "=label $passlabel") 
		if $passlabel;
}

my %options;

sub pass1
{
	push(@rules, "=countby 10", "=rulenum 1000");
	gensect(undef, 0, "any to any <in via =KEY>", %count_in);
	gensect(undef, 0, "any to any <out via =KEY>", %count_out);

	if (%count_udp_from || %count_udp_to) {
		push(@rules, "=skiprule udp from any to any",
			"=skipto not-counting-udp all from any to any");
		gensect(undef, 0,
			"<udp from> any <=KEY to> any",
			%count_udp_from);
		gensect(undef, 0,
			"<udp from> any <to> any <=KEY>",
			%count_udp_to);
		push(@rules, "=label not-counting-udp");
	}

	push(@rules, "=skiprule tcp from any to any # skipover tcp-from & to",
		"=skipto not-counting-tcp all from any to any");
	gensect(undef, 0,
		"<tcp from> any <=KEY to> any",
		%count_tcp_from);
	gensect(undef, 0,
		"<tcp from> any <to> any <=KEY>",
		%count_tcp_to);
	push(@rules, "=label not-counting-tcp");

	push(@rules, @count);

	push(@rules, "=rulenum 10000");

	# recv only happens on packets that we didn't generate
	if (@from_us_fules || @not_from_me_rules) {
		push(@rules,
			"=skipto done-from-us all from any to any in recv =IN",
			@from_me_rules,
			"=skipto done-not-from-us all from any to any",
			"=label done-from-us",
			@not_from_me_rules,
			"=label done-not-from-us");
	}

	if (@to_me_rules || @not_to_me_rules) {
		push(@rules,
			"=skipto done-to-us all from any to =ME",
			@not_to_me_rules,
			"=skipto done-not-to-us all from any to any",
			"=label done-to-us",
			@to_me_rules,
			"=label done-not-to-us");
	}

	gensect(undef, 0, "all from any to any in <recv =KEY>", %in_rules);
	gensect(undef, 0, "all from any to any out <xmit =KEY>", %out_rules);

	push(@rules, "pass tcp from any to any established");

	gensect(undef, 1, "all <from> not< =KEY> to any", %from_net_rules);
	gensect(undef, 1, "all from any <to> not< =KEY>", %to_net_rules);

	push(@rules, "=rulenum 20000");

	if (%udp_from_rules || %udp_to_rules) {
		push(@rules, "=skiprule udp from any to any",
			"=skipto not-filtering-udp all from any to any")
			if scalar(%udp_from_rules) + scalar(%udp_to_rules) > 4;
		gensect(undef, 0,
			"<udp from> any <=KEY to> any",
			%udp_from_rules);
		gensect(undef, 0,
			"<udp from> any <to> any <=KEY>",
			%udp_to_rules);
		push(@rules, "=label not-filtering-udp");
	}

	push(@rules, "=skiprule tcp from any to any",
		"=skipto not-filtering-tcp all from any to any");
	gensect(undef, 0,
		"<tcp from> any <=KEY> to any",
		%tcp_from_rules);
	gensect(undef, 0,
		"<tcp from> any <to> any <=KEY>",
		%tcp_to_rules);
	push(@rules, "=label not-filtering-tcp");

	push(@rules, "=rulenum 50000");

	if ($options{'DEFAULT-ACCEPT'}) {
		push(@rules, "pass all from any to any");
	} else {
		push(@rules, "deny all from any to any");
	}

	push(@rules, @count);
}

sub remove_action
{
	my ($rule) = @_;
	$rule =~ s/^(?:=skipto \S+|=skiprule|count|pass|deny|accpet|reject|unreach \S+|reset|divert \S+|tee \S+|skipto \S+)//
		or die "Cannot remove action from $rule";
	return $rule;
}

sub ipdots
{
        my ($addr) = @_;
	return '' unless $addr;
	return join('.',unpack('C4', $addr));
}


sub pass2
{
	my @n;
	my $waiting;
	for my $r (@rules) {
		my $x = $r;
		my $l;
		if ($x =~ s/^=skiprule/=skipto $genlabel/) {
			$l = $genlabel++;
		} else {
			#$x =~ s/^=deny/=skipto deny-target/;
			$x =~ s/^=deny/deny/;
		}
		while ($x =~ /=host:(\S+)/) {
			my $hname = $1;
			my ($net, $aliases, $addrtype, $length, $addr) 
				= gethostbyname($hname);
			die "could not find $hname" unless $addr;
			my $ip = ipdots($addr);
			$x =~ s/=host:\Q$hname\E/$ip/g;
		}
		if ($x =~ /=IN/) {
			for my $i (sort keys %interfaces) {
				my $y = $x;
				$y =~ s/=IN/$i/g;
				push(@n, $y);
			}
		} elsif ($x =~ /=US/) {
			my $l2 = $genlabel++;
			for my $n (@not_us) {
				my $y = remove_action($x);
				$y =~ s/=US/$n/g;
				push(@n, "=skipto $l2 $y");
			}
			for my $n (@us) {
				my $y = $x;
				$y =~ s/=US/$n/g;
				push(@n, $y);
			}
			push(@n, "=label $l2");
		} elsif ($x =~ /=ME/) {
			for my $i (sort keys %interfaces) {
				for $ip (@{$interfaces{$i}->{'IP'}}) {
					my $y = $x;
					$y =~ s/=ME/$ip/;
					push(@n, $y);
				}
			}
		} else {
			push(@n, $x);
		}
		push(@n, "=label $waiting") if $waiting;
		$waiting = $l;
	}
	@rules = @n;
}

my @numbers;
my %labels;
sub pass3
{
	my $rulenum = 1;
	my $inc = 1;
	my $c = 0;
	for my $r (@rules) {
		if ($r =~ /^=rulenum (\d+)/) {
			$rulenum = $1 if $1 > $rulenum;
			$r = undef;
		} elsif ($r =~ /^=countby (\d+)/) {
			$inc = $1;
			$r = undef;
		} elsif ($r =~ /^=label (\S+)/) {
			die "duplicate label $1" if exists $labels{$1};
			$labels{$1} = $c;
			$r = undef;
		} 
		$numbers[$c++] = $rulenum;
		$rulenum += $inc;
	}
}

sub pass4
{
	for (my $i = $#rules; $i >= 0; $i--) {
		my $r = $rules[$i];
		next unless $r;
		if ($r =~ /^=skipto (\S+)/) {
			die "no such label: $1" 
				unless exists $labels{$1};
			my $bti = $labels{$1};
			my $no = $numbers[$bti];
			$r =~ s/=skipto \S+/skipto $no/;
			my $j = $i+1;
			$j++ while ($j <= $#rules && ! $rules[$j]);
			if ($j >= $bti) {
				# this rule can be skipped.
				print DEBUG "optimizing away $numbers[$i]: $r\n";
				$r = undef;
			}
			$rules[$i] = $r;
		} 
	}
}

sub pass5
{
	print "# this was generated by $0\n";
	print "$ipfw -f flush\n";
	print "$ipfw add 1 pass all from any to any\n";
	for (my $i = 0; $i <= $#rules; $i++) {
		my $r = $rules[$i];
		next unless $r;
		my $n = $numbers[$i];
		print "$ipfw add $n $r\n";
	}
	print "$ipfw delete 1\n";
	print "$ipfw zero\n";
}

sub generate
{
	my (@opt) = @_;

	# don't allow others to pretend that they are us
	unshift(@not_from_me_rules, 
		"=skiprule all from any to any in recv lo*",
		"=deny all from =ME to any # ns-op");

	my @legal = qw(
		DEFAULT-ACCEPT
		INSECURE
	);
	my %legal;
	@legal{@legal} = @legal;
	for my $o (split(' ', "@opt")) {
		if ($legal{$o}) {
			$options{$o} = 1;
		} else {
			die "illegal option: $o";
		}
	}

	pass1();
	pass2();
	pass3();
	pass4();
	pass5();
}

1;


