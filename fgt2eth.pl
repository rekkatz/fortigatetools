#!/usr/bin/perl

# This work (and included software, documentation or other related items) is
# being provided by the copyright holders under the following license. By
# obtaining, using and/or copying this work, you (the licensee) agree that you
# have read, understood, and will comply with the following terms and conditions
#
# Permission to copy, modify, and distribute this software and its documentation
# with or without modification, for any purpose and without fee or royalty is
# hereby granted, provided that you include the following on ALL copies of the
# software and documentation or portions thereof, including modifications:
#
#   1. The full text of this NOTICE in a location viewable to users of the
#      redistributed or derivative work.
#   2. Notice of any changes or modifications to the files, including the date
#      changes were made.
#
#
# THIS SOFTWARE AND DOCUMENTATION IS PROVIDED "AS IS," AND COPYRIGHT HOLDERS
# MAKE NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO, WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR
# PURPOSE OR THAT THE USE OF THE SOFTWARE OR DOCUMENTATION WILL NOT INFRINGE ANY
# THIRD PARTY PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.
#
# COPYRIGHT HOLDERS WILL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL OR
# CONSEQUENTIAL DAMAGES ARISING OUT OF ANY USE OF THE SOFTWARE OR DOCUMENTATION.
#
# Title to copyright in this software and any associated documentation will at
# all times remain with copyright holders.
#
# Copyright: Fortinet Inc - 2005
#

# Fortinet EMEA Support
# This script converts a Fortigate verbose 3 sniffer output file to a file that
# can be opened by Ethereal. It uses the text2pcap binary included in the Ethereal package.
# It is supplied as is and no technical support will be provided for it.

  my $version 		      = "Dec 19 2014";

# ------------------ don't edit after this line -------------------------------
  use strict;
  use Getopt::Long;
  use FileHandle;
  use Config;
  use vars qw ($debug $help $vers $in $out $lines $demux $childProcess);
  use Data::Dumper;

# Autoflush
    $| = 1;

# Global variables
  my $line_count		        = 0;
  my ($fh_in, $fh_out);
  my @fields 			        = {};
  my @subhexa 			        = {};
  my ($offset,$hexa,$garbage)   = "";
  my %outfileList;
  my %outfilenameList;


  # Get commandLine arguments
  getArgs();

  # In order to support real-time display in wireshark/ethereal, we need to pipe
  # our stdout into wireshark stdin, which is not allowed by the OS...
  # The trick consists in creating a child process with the appropriate anonymous
  # pipes already in place and delegate the work to the child.
  spawnPipedProcess();

  open(fh_in,  '<', $in)  or die "Cannot open file ".$in." for reading\n";


# Convert
  if( $debug ) {
    print STDERR "Conversion of file ".$in." phase 1 (FGT verbose 3 conversion)\n";
    print STDERR "Output written to ".$out.".\n";
  }

  my @packetArray = ();

  #Parse the entire source file
  my $DuplicateESP = 0;
  my $eth0 = 0;
  my $skipPacket = 0;

followMode:
    while (<fh_in>) {
		s/^\d{2}(\d{4})/0x$1/;
        #and build an array from the current packet
        if( isTimeStamp() ) {
			$skipPacket = 0;
            if( not $demux and /eth0/ ) {
                $eth0++;
                $skipPacket = 1;
            }

       	    # Select the appropriate output file for the interface.
       	    $fh_out = getOutputFileHandler() if defined $demux;
			$skipPacket |= convertTimeStamp();
		 } elsif	( isHexData() and not $skipPacket ) {
			buildPacketArray();
			adjustPacket();
			_startConvert();
		}
    }

    if( $out eq "-" ) {
        # no more incoming data. Wait 2 seconds and try again
        sleep 2;
        goto followMode;
    }

	print "** Skipped $eth0 packets captured on eth0\n" if $eth0;

# Close files and start text2pcap if needed
	close (fh_in)  or die "Cannot close file ".$in."\n";
	my $text2pcap  = getText2PcapCmd();
	foreach my $intf( keys %outfileList ) {
		close $outfileList{ $intf };
		my $filename_in = $outfilenameList{$intf};
		my $filename_out = $filename_in;
		$filename_out    =~ s/\.tmp$/\.pcap/;
		system("$text2pcap $filename_in $filename_out");
		unlink($filename_in);
	}


	if( $debug ) {
		print STDERR "Output file to load in Ethereal is \'".$out."\'\n";
		print STDERR "End of script\n";
	}


sub isHexData   { /^(0x[0-9a-f]+[ \t\xa0]+)/ }
sub isTimeStamp { /^[0-9]+[\.\-][0-9]+/      }
# /Dummy comment to workaround Komodo parsing

sub buildPacketArray {
	my $line = 0;
	@packetArray = ();

	do {
		# Format offset from 0x0000 to 000000 (text2pcap requirement)
		s/^0x([\da-f]{4})/00$1/;
		if ( s/^([\da-f]{6})\s+// ) {
			# Remove ASCII translation at the end of the line
			s/\s\s+.*//;
			my @bytes  = /([\da-f]{2})\s?([\da-f]{2})?/g;
			$#bytes = 15;
			push @packetArray => @bytes;
		}
		$_ = <fh_in>;
	} until ( /^\s*$/ );
}

sub convertTimeStamp {
	# Keep timestamps.
	return 1 if /truncated\-ip \- [0-9]+ bytes missing!/ ;
	if ( /^([0-9]+)\.([0-9]+) / )
    {
        my $packet = 1;
        my $time = $1;

		# Extract days
		my $nbDays	= int($time / 86400);
		my $day 	= sprintf("%0.2d", 1+$nbDays);
		$time 		= $time % 86400;

        # Extract hours
        my $hour = int($time / 3600 );
        $time = $time % 3600;

        # Extract minutes
        my $minute = int( $time / 60);
        $time = $time % 60;


        # and remaining seconds
        my $sec = $time;

        _print("01/$day/2005 " . $hour . ":" . $minute . ":" . $sec . ".$2\n");
    } elsif ( /^(\d+-\d+-\d+ \d+:\d+:\d+\.\d+) / ) {
        # absolute timestamp
        my $timestamp   = $1;
        $timestamp      =~ s/(\d+)-(\d+)-(\d+)/$3\/$2\/$1/;
        _print("$timestamp\n");
    }
	# Check if line is a duplicate ESP packet (FGT display bug)
	return 0;

}

sub getOutputFileHandler
{
    my ($currIntf) =  $_ =~ / (\S+) (?:out|in) /;
    $currIntf = "[noIntf]" if $currIntf eq "";
    if( not defined( $outfileList{$currIntf} )) {
        my $filename = $out ? $out : $in;
        $filename =~ s/\.zip$//g;
        my $suffix = ".$currIntf.tmp";
        $suffix    =~ s/\//-/g;     # Escape '/' char in interface name
        $filename .= $suffix;
        open( $outfileList{$currIntf}, "> $filename");
        $outfilenameList{$currIntf} = $filename;
    }
    return $outfileList{$currIntf};
}


#----------
# name : adjustPacket
# description:
#  Applies changes to the current packetArray to make it convertible into
#  ethereal format.
#     - Removes internal Fortigate tag when capture interface is any.
#
sub adjustPacket {

  next unless $packetArray[0][0] =~ /0x0000/;
  stripBytes( 7, 1 ) if $packetArray[0][8] =~ /0800/;
  stripBytes( 7, 1 ) if $packetArray[0][7] =~ /8893/;
  addHdrMAC()        if $packetArray[0][1] =~ /45[0c]0/;
  $packetArray[0][7] =~ s/8890|8891/0800/ if $packetArray[0][0] =~ /0x0000/;
}

sub addHdrMAC
{
  my $nbRows = scalar @packetArray;

  # And populate 0x0000 line
  unshift @packetArray => qw( 00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 );
  # left shift the IP ver+IHL (4500)
  stripBytes(14,2);
}

sub stripBytes
{
  my $start         = shift;
  my $nbBytes       = shift;

  my @subArray = @packetArray[$start..$#packetArray-1];
  shift @subArray for 1..$nbBytes;
  @packetArray = (@packetArray[0..$start-1],@subArray);
}

sub _startConvert {
  LINE:
    #Initialisation
    my $hexa = "";
    my $garbage = "";

	my $offset = 0;
	foreach my $byte (@packetArray) {
		_print( sprintf( "%0.6x ", $offset )) unless $offset % 16;
		_print( " ". $byte);
		$offset ++;
		_print("\n") unless $offset % 16;
	}
    _print( "\n");

     $line_count++;
    if (defined($lines)) {
		if ($line_count >= $lines) {
		    print STDERR "Reached max number of lines to write in output file\n";
		    last LINE;
        }
    }
}

sub spawnPipedProcess
{
    # Spawn a new process to pipe ourselves with text2pcap
    my( $fgt2eth, $text2pcap, $wireshark );

    # Are we already in the pipelined session ?
    return if $childProcess or $demux;

    $fgt2eth    = $0 . " -in \"$in\" -out \"$out\" -childProcess";
    $text2pcap  = getText2PcapCmd(). "- ";
    $wireshark  = getWiresharkCmd();


    my $cmd = "$fgt2eth | $text2pcap";

    # Prepare output filename
    if( $out eq "-" ) {
        $cmd .= "- | $wireshark";
    } else {
        $out  = $in . ".pcap" unless $out;
        $cmd .= " $out";
    }

    print STDERR $cmd if $debug;

    open( CMD, "$cmd |" );
    while( <CMD> ) {
        _print($_);
    }

    close CMD;

    # Make sure we don't go further in the parent process
    exit;
}

sub getText2PcapCmd
{
    my $cmd;

    my @windowsPath = qw(
                       c:\\Progra~1\\Ethereal
                       c:\\Progra~1\\Wireshark
                    );

    if ($ENV{'OS'} =~ /windows/i) {
        if( $Config{osname} =~ /cygwin/i ) {
            #OS is Windows running Cygwin
            $cmd =  "'/cygdrive/c/Program Files/Wireshark/text2pcap'";
        } else {
            # OS is windows
            my $dir;
            for $dir( @windowsPath ) {
                $cmd = "$dir\\text2pcap.exe" if -e "$dir\\text2pcap.exe";
            }
        }
    } else {
        # OS is linux :-)
        $cmd = "text2pcap";
    }

    # Sanity
    die "Text2Pcap could not be found\n" unless $cmd;

    $cmd .= " -q -t \"%d/%m/%Y %H:%M:%S.\" ";

    return $cmd;
}

sub getWiresharkCmd
{
    my $cmd;

    my @windowsPath = qw(
                       c:\\Progra~1\\Wireshark
                    );

    if ($ENV{'OS'} =~ /windows/i) {
        if( $Config{osname} =~ /cygwin/i ) {
            # OS is Windows running Cygwin
            $cmd = "'/cygdrive/c/Program Files/Wireshark/wireshark'";
        } else {
            # OS is windows
            my $dir;
            for $dir( @windowsPath ) {
                $cmd = "$dir\\wireshark.exe" if -e "$dir\\wireshark.exe";
            }
        }
    } else {
        # OS is linux :-)
        $cmd = "wireshark";
    }

    # Sanity
    die "wireshark could not be found\n" unless $cmd;

    $cmd .= " -k -i -";

    return $cmd;
}

sub _print{

    my $msg = shift;

    if( defined $fh_out ) {
        print $fh_out $msg;
    } else {
        print $msg;
    }
}

sub getArgs
{

   # Control command line options
   GetOptions(
	"debug"	  	=> \$debug,			# use -debug to turn on debug
  	"version"       => \$vers,    		        # use -version to display version
	"help" 	  	=> \$help,			# use -help to display help page
	"in=s"    	=> \$in,			# use -in  <filename> to specify an input file
	"out=s"   	=> \$out,			# use -out <filename> to specify an output file
        "lines=i"  	=> \$lines,			# use -lines <number> to stop after <number> lines written
        "demux"         => \$demux,                     # use -demux to create one pcap per intf
        "childProcess"  => \$childProcess,
	);

  if ($help) {
    Print_help();
    exit;
    }

  if ($vers) {
    Print_version();
    exit;
    }

  # Sanity checks
  if (not(defined($in))) {
    Print_usage();
    exit;
    }
}

#------------------------------------------------------------------------------
 sub Print_usage {

  print <<EOT;
Version : $version
Usage : fgt2eth.pl -in <input_file_name>

Mandatory argument are :
    -in  <input_file>     Specify the file to convert (FGT verbose 3 text file)

Optional arguments are :
    -help                 Display help only
    -version              Display script version and date
    -out <output_file>    Specify the output file (Ethereal readable)
                By default <input_file>.pcap is used
                - will start wireshark for realtime follow-up
    -lines <lines>        Only convert the first <lines> lines
    -demux            Create one pcap file per interface (verbose 6 only)
    -debug                Turns on debug mode

EOT
}

#------------------------------------------------------------------------------
 sub Print_help {

  print <<EOT;
This script permits to sniff packets on the fortigate with built-in sniffer
diag sniff interface <interface> verbose 3 filters '....'
and to be able to open the captured packets with Ethereal free sniffer.

* What do I need to know about this script ?
    - It can be sent to customers, but it is given as is.
    - No support is available for it as it is not an 'offical' fortinet product.
    - It should run on windows and linux as long as perl is installed.
    - To install perl on windows system,
             http://www.activestate.com/Products/ActivePerl/
    - All lines from the source file that do not begin with '0x' are ignored.
    - Do not add garbage characters to the file during the capture
    - If possible do not hit the keyboard during capture.;

Remarks concerning this script can be sent to eu_support\@fortinet.com
Thanks to Claudio for this great idea and Ellery from Vancouver Team for the timestamps

Cedric

EOT

}
#------------------------------------------------------------------------------

sub Print_version {
  print "\nVersion : ".$version."\n\n";
}

sub myDump {
	my $object = shift;

    my $dumper = new Data::Dumper([$object]);
    $dumper->Maxdepth(3);
    print STDERR $dumper->Dump;
}
