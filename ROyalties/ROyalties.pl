# This plugin was inspired by the "LatamChecksum" plugin made by OvoKore, and... adapted by AlisonRag, and Unknown.
# Thank you all for the amazing work! <3

package ROyalties;

use strict;
use Plugins;
use Globals;
use Misc;
use AI;
use Network::Send ();
use IO::Socket::INET;
use Log qw(message warning error);
use Encode;
use File::Spec;
use Cwd 'abs_path';

our $sock     = undef;
our $auth_ok  = 0;
our $auth_token = undef;

my $counter = 0;
my $enabled = 0;

Plugins::register("ROyalties", "ROyalties checksum plugin", \&unload);

my $hooks = Plugins::addHooks(
	['start3', \&checkServer, undef],
);
my $base_hooks;

sub checkServer {
	my $master = $masterServers{ $config{master} };
	if ($master->{serverType} eq 'ROla') {
		$base_hooks = Plugins::addHooks(
			[ 'serverDisconnect/fail',    \&serverDisconnect, undef ],
			[ 'serverDisconnect/success', \&serverDisconnect, undef ],
			[ 'Network::serverSend/pre',  \&serverSendPre,    undef ]
		);
	}
}

sub unload {
	Plugins::delHooks($base_hooks) if $base_hooks;
	Plugins::delHooks($hooks) if $hooks;
	if ($sock) { close($sock); undef $sock; }
	$enabled = 0;
	$auth_ok = 0;
}

sub serverDisconnect {
	warning "[ROyalties] Disconnected. Checksum disabled.\n";
	$enabled = 0;
	$counter = 0;
	$auth_ok = 0;
	if ($sock) { close($sock); undef $sock; }
}

sub read_key {
	my $plugin_path = abs_path(__FILE__);
	$plugin_path =~ s|\\|/|g;
	$plugin_path =~ s|/[^/]+$||;
	my $file = File::Spec->catfile($plugin_path, 'key.txt');

	if (open my $fh, '<', $file) {
		while (<$fh>) {
			if (/^KEY=(.+)/) {
				chomp($auth_token = $1);
				last;
			}
		}
		close $fh;
	} else {
		warning "[ROyalties] Could not open $file: $!\n";
	}
}

sub authenticate {
	return 1 if $auth_ok;

	read_key() unless defined $auth_token;
	unless ($auth_token) {
		warning "[ROyalties] No valid key found — did you forget to set it in key.txt?\n";
		warning "[ROyalties] Triggering disconnect.\n";
		Commands::run("quit 1");
		return 0;
	}

	$sock = IO::Socket::INET->new(
		PeerAddr => '3.72.13.195',
		PeerPort => 4000,
		Proto    => 'tcp',
		Timeout  => 2,
	) or do {
		warning "[ROyalties] Could not connect: $!\n";
		return 0;
	};
	$sock->autoflush(1);

	print $sock "AUTH $auth_token\n";

	my $response;
	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		alarm 2;
		$response = <$sock>;
		alarm 0;
	};

	if ($@ || !defined $response) {
		warning "[ROyalties] AUTH timeout or error.\n";
		close($sock); undef $sock;
		return 0;
	}

	chomp $response;
	if (index($response, 'Autenticado') >= 0) {
		$auth_ok = 1;
		message "[ROyalties] Auth OK.\n";
		return 1;
	} else {
		warning "[ROyalties] Auth failed: $response\n";
		close($sock); undef $sock;
		warning "[ROyalties] Triggering disconnect.\n";
		Commands::run("quit 1");
		return 0;
	}
}

sub calc_checksum {
	my ($packet_bytes) = @_;

	print $sock pack("N", $counter) . $packet_bytes;

	my $response;
	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		alarm 2;
		$response = <$sock>;
		alarm 0;
	};

	return 0 if $@ || !defined $response;
	chomp $response;

	if ($response =~ /^0x?([0-9a-fA-F]{1,2})$/) {
		return hex($1);
	}
	elsif ($response =~ /^(\d{1,3})$/) {
		my $v = $1 + 0;
		return ($v <= 255) ? $v : 0;
	}

	warning "[ROyalties] Server message: $response\n";

	my $message = decode("UTF-8", substr($response, 2));
    $message =~ s/\0.*$//s;

	if ($message =~ /desconectado por outro login/i) {
		warning "[ROyalties] Triggering disconnect.\n";
		Commands::run("quit 1");
	}

	return 0;
}

sub serverSendPre {
	my (undef, $args) = @_;
	my $msg = $args->{msg};
	return if ref($::net) eq 'Network::XKore';

	my $id0 = unpack("C", substr($$msg, 0, 1));
	my $id1 = unpack("C", substr($$msg, 1, 1));
	my $messageID = sprintf("%02X%02X", $id1, $id0);

	if ($counter == 0) {
		if ($messageID eq '0B1C') {
			$enabled = 1;
			$$msg = pack("C*", 0x1C, 0x0B, 0x36);
		}
		elsif ($messageID eq $messageSender->{packet_lut}{map_login}) {
			$enabled = 1;
			$messageSender->sendPing();
		}
	}

	if (!$enabled || $::net->getState() < 4) {
		$counter++;
		return;
	}

	authenticate() unless $auth_ok;
	return unless $auth_ok;

	my $checksum = calc_checksum($$msg);
	if ($checksum > 0 && $checksum <= 255 && $messageID ne '0B1C') {
		$$msg .= pack("C", $checksum);
	}
	$counter++;
}

1;
