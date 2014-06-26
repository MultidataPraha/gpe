#!/exlibris/aleph/a22_1/product/bin/perl

###########################################################
#
# (c) 2013, 2014 MULTIDATA Praha spol. s r.o.
#
# gpe2.pl 20140625 aleph - gpe interface (dev)
#
###########################################################

use strict;
use warnings;
use diagnostics;
use utf8;
binmode STDOUT, ":utf8";
use CGI;

use Crypt::OpenSSL::RSA;
use File::Slurp;
use MIME::Base64;
use DBI;
use POSIX qw(strftime);
use Time::HiRes q/gettimeofday/;
use File::Basename;

my $nok = 0;

my $signature;
my $tmpsig;

my $q = CGI->new;

my ( $sql, $sth, $dbh );

my %gpe;
my %config;

die "missing DOCUMENT_ROOT environment variable" unless $ENV{'DOCUMENT_ROOT'};
$ENV{'alephe_tab'} = $ENV{'DOCUMENT_ROOT'} . '/../../tab';

my $script_name;
$script_name = basename( $q->script_name(), ".pl" ) if $q->script_name();
$script_name = basename( $0, ".pl" ) unless $script_name;

my $config_file = $ENV{'alephe_tab'} . '/' . $script_name . '.cfg';

die "cannot open config file $config_file: $!"
    unless read_config($config_file);

my $adm_library;
my $key_file     = $config{'gpe_public_key'};
my $opac_err_url = $config{'opac_err_url'};
my $opac_ok_url  = $config{'opac_ok_url'};
my $opac_nok_url = $config{'opac_nok_url'};
$config{'debug'} = 0 unless defined $config{'debug'};

$gpe{'MERCHANTNUMBER'} = $config{'MERCHANTNUMBER'};

$ENV{'aleph_db'}   = $config{'aleph_db'}   if defined $config{'aleph_db'};
$ENV{'ORACLE_SID'} = $config{'ORACLE_SID'} if defined $config{'ORACLE_SID'};
$ENV{'ORACLE_HOME'} = $config{'ORACLE_HOME'}
    if defined $config{'ORACLE_HOME'};
$ENV{'LOGDIR'}   = $config{'LOGDIR'}   if defined $config{'LOGDIR'};
$ENV{'NLS_LANG'} = $config{'NLS_LANG'} if defined $config{'NLS_LANG'};

my $logfile_name = $ENV{"LOGDIR"} . '/' . $script_name . '.log';
open my $logfile, ">>", $logfile_name
    || die "cannot open logfile $logfile_name: $!";

binmode( $logfile, ":unix" );
open STDERR, ">&", $logfile;

my $key_string = read_file( $ENV{"alephe_tab"} . "/$key_file" )
    || die "cannot read public key";

my $rv;

eval {

    write_debug( $q->param('MD') );
    die "missing MERCHANTNUMBER cfg" unless defined $gpe{'MERCHANTNUMBER'};
    die "missing aleph_db cfg / env"
        unless $ENV{'aleph_db'} || $ENV{'ORACLE_SID'};
    die "missing ORACLE_HOME cfg / env" unless $ENV{'ORACLE_HOME'};

    my ($md,             $md_z63_bor_id, $md_amount,
        $md_adm_library, $md_client_ip,  $md_ordernumber
    ) = split( /#/, $q->param('MD') );

    $adm_library = $md_adm_library;

    write_debug(
        "md $md, bor_id $md_z63_bor_id, amount $md_amount, adm $md_adm_library, ip $md_client_ip, ordernumber $md_ordernumber"
    );

    my $plaintext0 = join( '|',
        $q->param('OPERATION'),   $q->param('ORDERNUMBER'),
        $q->param('MERORDERNUM'), $q->param('MD'),
        $q->param('PRCODE'),      $q->param('SRCODE'),
        $q->param('RESULTTEXT') )
        || die "$!";

    my $plaintext1 = join( '|',
        $q->param('OPERATION'),   $q->param('ORDERNUMBER'),
        $q->param('MERORDERNUM'), $q->param('MD'),
        $q->param('PRCODE'),      $q->param('SRCODE'),
        $q->param('RESULTTEXT'),  $gpe{'MERCHANTNUMBER'} )
        || die "$!";

    write_debug("plaintext1 $plaintext1");
    my $rsa_pub = Crypt::OpenSSL::RSA->new_public_key($key_string)
        || die "$!";

    $signature = decode_base64( $q->param('DIGEST') );
    $tmpsig    = $q->param('DIGEST');

    unless ( $rsa_pub->verify( $plaintext0, $signature ) ) {
        write_log("DIGEST ERROR");
        $nok = 1;
    }

    $signature = decode_base64( $q->param('DIGEST1') );
    $tmpsig    = $q->param('DIGEST1');

    unless ( $rsa_pub->verify( $plaintext1, $signature ) ) {
        write_log("DIGEST1 ERROR");
        $nok = 1;
    }

    $nok = 1 unless $q->param('PRCODE') == 0;
    $nok = 1 unless $q->param('SRCODE') == 0;

    if ($nok) {
        write_log("GPE ERROR, redirect to opac_nok_url: ORDERNUMBER "
                . $q->param('ORDERNUMBER')
                . ", PRCODE "
                . $q->param('PRCODE')
                . ", SRCODE "
                . $q->param('SRCODE')
                . ", RESULTTEXT "
                . $q->param('RESULTTEXT') );
        print $q->redirect($opac_nok_url);
        exit;
    } ## end if ($nok)

    my $connect_string;
    $connect_string = "dbi:Oracle:$ENV{'aleph_db'}" unless $ENV{'ORACLE_SID'};
    $connect_string = "dbi:Oracle:" if $ENV{'ORACLE_SID'};
    $dbh = DBI->connect( "$connect_string", 'aleph', 'aleph',
        { RaiseError => 1, AutoCommit => 0, Warn => 1 } );

    my $z31_payment_date_key = strftime( q/%Y%m%d%H%M/, localtime() );

    $sql = <<"EOT";
       select distinct regexp_replace(Z31_PAYMENT_IDENTIFIER,'GPE-.*-','')
       from ${adm_library}.z31
       where Z31_STATUS = 'O'
       and Z31_CREDIT_DEBIT = 'D'
       and Z31_PAYMENT_CATALOGER = 'GPE1'
       and Z31_PAYMENT_IDENTIFIER like 'GPE-'||?||'-%'
EOT

    $sth = $dbh->prepare($sql);
    $sth->execute( $q->param('ORDERNUMBER') );
    my ($old_sum) = $sth->fetchrow_array();

    $sql = <<"EOT";
       select sum(Z31_SUM)
       from ${adm_library}.z31
       where Z31_STATUS = 'O'
       and Z31_CREDIT_DEBIT = 'D'
       and Z31_PAYMENT_CATALOGER = 'GPE1'
       and Z31_PAYMENT_IDENTIFIER like 'GPE-'||?||'-%'
EOT

    $sth = $dbh->prepare($sql);
    $sth->execute( $q->param('ORDERNUMBER') );
    my ($new_sum) = $sth->fetchrow_array();

    $dbh->rollback;

    die "sum == 0" unless $new_sum;

    write_log("old_sum $old_sum != new_sum $new_sum")
        if $old_sum && $new_sum && $new_sum != $old_sum;

    $sql = <<"EOT";
       update ${adm_library}.z31
       set
         Z31_PAYMENT_CATALOGER = 'GPE2',
         Z31_STATUS = 'C',
         Z31_PAYMENT_DATE_KEY = ?
       where Z31_STATUS = 'O'
       and Z31_CREDIT_DEBIT = 'D'
       and Z31_PAYMENT_CATALOGER = 'GPE1'
       and Z31_PAYMENT_IDENTIFIER like 'GPE-'||?||'-%'
EOT

    $sth = $dbh->prepare($sql);

    my $rows
        = $sth->execute( $z31_payment_date_key, $q->param('ORDERNUMBER') );

    $dbh->commit;
    $rv = $sth->rows;
    write_debug( "GPE2, Z31_STATUS = 'C' $rv @ line " . __LINE__ );

    write_log("OK, redirect to opac_ok_url: ORDERNUMBER "
            . $q->param('ORDERNUMBER')
            . ", ADM: "
            . $adm_library
            . ", AMOUNT "
            . $new_sum
            . ", closed $rows z31(s)" );

    print $q->redirect($opac_ok_url);

} or do {

    print $q->redirect($opac_err_url);

    $@ = "unknown error" unless $@;
    chomp $@;
    $@ =~ s/\n/#/g;
    write_log("ERR: $@");

};

exit;

sub get_time3 {
    my ( $seconds, $microseconds ) = gettimeofday;
    return strftime( q/%FT%T/, localtime($seconds) )
        . sprintf( ".%03d", $microseconds / 1000 );
}

sub read_config {
    my $cfg_file_name = shift;
    open my $cfg_file, "<", $cfg_file_name || return;
    while (<$cfg_file>) {
        if (/^[;!\#]/) {
            next;
        }
        if (/^\s*([a-z][a-z0-9_]*)\s*=\s*(.*?)\s*$/i) {
            $config{ ($1) } = $2;
        }
    }
    close $cfg_file;
} ## end sub read_config

sub write_debug {
    write_log( "debug: " . shift(@_) ) if $config{'debug'};
}

sub write_log {
    print $logfile get_time3(), " ", shift(@_), "\n";
}

