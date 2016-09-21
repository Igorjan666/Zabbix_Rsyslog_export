#! /usr/bin/perl

#   A skeleton for a perl rsyslog output plugin
#   Copyright (C) 2014 by Adiscon GmbH
#
#   This file is part of rsyslog.
#  
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#   
#         http://www.apache.org/licenses/LICENSE-2.0
#         -or-
#         see COPYING.ASL20 in the source distribution
#   
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#use 5.010;
use strict;
use warnings;
use JSON::RPC::Legacy::Client;
use Data::Dumper;
use Config::General;
use CHI;
use List::MoreUtils qw (any);
use English '-no_match_vars';
use Readonly;
use MIME::Base64 qw(encode_base64);
use IO::Socket::INET;
our $VERSION = 2.0;
use IO::Handle;
use IO::Select;



# skeleton config parameters
my $maxAtOnce = 20;	# max nbr of messages that are processed within one batch
my $pollPeriod = 10;

Readonly my $CACHE_TIMEOUT => 600;
Readonly my $CACHE_DIR     => '/tmp/zabbix_syslog_cache';

my $conf   = Config::General->new('/usr/local/etc/zabbix_syslog.cfg');
my %Config = $conf->getall;

#Authenticate yourself
my $client = JSON::RPC::Legacy::Client->new();
my $url = $Config{'url'} || die "URL is missing in zabbix_syslog.cfg\n";
my $user = $Config{'user'} || die "API user is missing in zabbix_syslog.cfg\n";
my $password = $Config{'password'} || die "API user password is missing in zabbix_syslog.cfg\n";
my $server = $Config{'server'} || die "server hostname is missing in zabbix_syslog.cfg\n";


my $debug = $Config{'debug'};
my ( $authID, $response, $json );
my $id = 0;


# App logic global variables
#my $OUTFILE;			# Output Filehandle


sub onInit {
	#	Do everything that is needed to initialize processing (e.g.
	#	open files, create handles, connect to systems...)

	#open $OUTFILE, ">>/tmp/logfile" or die $!;
	#$OUTFILE->autoflush(1);
	
}

#to global
my $message;
my $ip;
my $ipv4_octet;
my $cache;
my $hostname;






sub onReceive {
	#	This is the entry point where actual work needs to be done. It receives
	#	a list with all messages pulled from rsyslog. The list is of variable
	#	length, but contains all messages that are currently available. It is
	#	suggest NOT to use any further buffering, as we do not know when the
	#	next message will arrive. It may be in a nanosecond from now, but it
	#	may also be in three hours...
	
	foreach(@_ ) {
			
			#кишки старого скрипта https://habrahabr.ru/company/zabbix/blog/252915/
			
			$message = $_   || die
				"Syslog message required as an argument\n";  #Grab syslog message from rsyslog

			
			if ( $debug > 0 ) { print Dumper @_; };

			#get ip from message
			
			#IP regex patter part
			$ipv4_octet = q/(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/;

			if ( $message =~ / \[ ((?:$ipv4_octet[.]){3}${ipv4_octet}) \]/msx ) {
				$ip = $1;
			}
			else {
				die "No IP in square brackets found in '$message', cannot continue\n";
			}

			$cache = CHI->new(
				driver   => 'File',
				root_dir => $CACHE_DIR,
			);

			$hostname = $cache->get($ip);

			if ( !defined $hostname ) {

				$authID = login();
				my @hosts_found;
				my $hostid;
			foreach my $host ( hostinterface_get() ) {

				$hostid = $host->{'hostid'};

				if ( any { /$hostid/msx } @hosts_found ) {
						next;
				}    #check if $hostid already is in array then skip(next)
				else { push @hosts_found, $hostid; }

				###########now get hostname
				if ( get_zbx_trapper_syslogid_by_hostid($hostid) ) {

					my $result = host_get($hostid);

					#return hostname if possible
					if ( $result->{'host'} ) {

						if ( $result->{'proxy_hostid'} == 0 )    #check if host monitored directly or via proxy
															{
						#lease $server as is
						}
						else {
						#assume that rsyslogd and zabbix_proxy are on the same server
						$server = 'localhost';
						}
						$hostname = $result->{'host'};
					}

				}

			}
		logout();
		$cache->set( $ip, $hostname, $CACHE_TIMEOUT );
			}

	zabbix_send( $server, $hostname, 'syslog', $message );
	}
}


#______SUBS
sub login {

    $json = {
        jsonrpc => '2.0',
        method  => 'user.login',
        params  => {
            user     => $user,
            password => $password

        },
        id => $id++,
    };

    $response = $client->call( $url, $json );

    # Check if response was successful
    die "Authentication failed\n" unless $response->content->{'result'};

    if ( $debug > 0 ) { print Dumper $response->content->{'result'}; }

    return $response->content->{'result'};

}

sub logout {

    $json = {
        jsonrpc => '2.0',
        method  => 'user.logout',
        params  => {},
        id      => $id++,
        auth    => $authID,
    };

    $response = $client->call( $url, $json );

    # Check if response was successful
    warn "Logout failed\n" unless $response->content->{'result'};

    return;
}

sub hostinterface_get {

    $json = {

        jsonrpc => '2.0',
        method  => 'hostinterface.get',
        params  => {
            output => [ 'ip', 'hostid' ],
            filter => { ip => $ip, },

            #    limit => 1,
        },
        id   => $id++,
        auth => $authID,
    };

    $response = $client->call( $url, $json );

    if ( $debug > 0 ) { print Dumper $response; }

    # Check if response was successful (not empty array in result)
    if ( !@{ $response->content->{'result'} } ) {
        logout();
        die "hostinterface.get failed\n";
    }

    return @{ $response->content->{'result'} }

}

sub get_zbx_trapper_syslogid_by_hostid {

    my $hostids = shift;

    $json = {
        jsonrpc => '2.0',
        method  => 'item.get',
        params  => {
            output  => ['itemid'],
            hostids => $hostids,
            search  => {
                'key_' => 'syslog',
                type   => 2,          #type => 2 is zabbix_trapper
                status => 0,

            },
            limit => 1,
        },
        id   => $id++,
        auth => $authID,
    };

    $response = $client->call( $url, $json );
    if ( $debug > 0 ) { print Dumper $response; }

    # Check if response was successful
    if ( !@{ $response->content->{'result'} } ) {
        logout();
        die "item.get failed\n";
    }

    #return itemid of syslog key (trapper type)
    return ${ $response->content->{'result'} }[0]->{itemid};
}

sub host_get {
    my $hostids = shift;

    $json = {

        jsonrpc => '2.0',
        method  => 'host.get',
        params  => {
            hostids => [$hostids],
            output  => [ 'host', 'proxy_hostid', 'status' ],
            filter => { status => 0, },    # only use hosts enabled
            limit  => 1,
        },
        id   => $id++,
        auth => $authID,
    };

    $response = $client->call( $url, $json );

    if ( $debug > 0 ) { print Dumper $response; }

    # Check if response was successful
    if ( !$response->content->{'result'} ) {
        logout();
        die "host.get failed\n";
    }
    return ${ $response->content->{'result'} }[0];    #return result
}

sub zabbix_send {
    my $zabbixserver = shift;
    my $hostname     = shift;
    my $item         = shift;
    my $data         = join (' ', @_ );
    #my $zabbixserver = "";
    #    my $hostname = "";
    #    my $item = "";
    #    my $data = "";
    #    ($zabbixserver,$hostname,$item,$data) = @_;

#syslog("info", "Шлю");
#syslog("info", $data);

    Readonly my $SOCK_TIMEOUT     => 10;
    Readonly my $SOCK_RECV_LENGTH => 1024;

    my $result;

    my $request =
      sprintf
      "<req>\n<host>%s</host>\n<key>%s</key>\n<data>%s</data>\n</req>\n",
      encode_base64($hostname), encode_base64($item), encode_base64($data);

    my $sock = IO::Socket::INET->new(
        PeerAddr => $zabbixserver,
        PeerPort => '10051',
        Proto    => 'tcp',
        Timeout  => $SOCK_TIMEOUT
    );

    die "Could not create socket: $ERRNO\n" unless $sock;
    $sock->send($request);
    my @handles = IO::Select->new($sock)->can_read($SOCK_TIMEOUT);
    if ( $debug > 0 ) { print "item - $item, data - $data\n"; }

    if ( scalar(@handles) > 0 ) {
        $sock->recv( $result, $SOCK_RECV_LENGTH );
        if ( $debug > 0 ) {
            print "answer from zabbix server $zabbixserver: $result\n";
        }
    }
    else {
        if ( $debug > 0 ) { print "no answer from zabbix server\n"; }
    }
    $sock->close();


    return;
}



sub onExit {
	#	Do everything that is needed to finish processing (e.g.
	#	close files, handles, disconnect from systems...). This is
	#	being called immediately before exiting.
	#close($OUTFILE);
	
}

#-------------------------------------------------------
#This is plumbing that DOES NOT need to be CHANGED
#-------------------------------------------------------
onInit(); 

# Read from STDIN
$STDIN = IO::Select->new();
$STDIN->add(\*STDIN);

# Enter main Loop

my $keepRunning = 1; 
while ($keepRunning) {
	my @msgs; 
	my $stdInLine; 
	my $msgsInBatch = 0; 
	while ($keepRunning) {
		#sleep(1);
		# We seem to have not timeout for select - or do we?
		if ($STDIN->can_read($pollPeriod)) {
			$stdInLine = <STDIN>;
			# Catch EOF, run onRecieve one last time and exit
			if (eof()){
				$keepRunning = 0;
				

				last;
			}
			if (length($stdInLine) > 0) {
				

				push (@msgs, $stdInLine); 

				$msgsInBatch++;
				if ($msgsInBatch >= $maxAtOnce) {
				
					last;
				}
			}
		}
	}
	
	onReceive(@msgs);
}

onExit(); 
