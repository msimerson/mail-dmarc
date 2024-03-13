#!/usr/bin/perl
# VERSION 1.12

use strict;
use warnings;

use CPAN;
use Data::Dumper;
use English qw( -no_match_vars );

my $apps = [
#   { app => 'mysql-server-8', info => { port => 'mysql82-server', dport=>'mysql82',  yum =>'mysql-server'} },
#   { app => 'apache24'      , info => { port => 'apache24',       dport=>'',     yum => 'httpd' } },
];

$EUID == 0 or die "You will have better luck if you run me as root.\n"; ## no critic (Carp)

my @failed;
foreach ( @$apps ) {
    my $name = $_->{app} or die 'missing app name'; ## no critic (Carp)
    install_app( $name, $_->{info} );
};

foreach ( get_perl_modules() ) {
    my $module = $_->{module} or die 'missing module name'; ## no critic (Carp)
    next if $module eq 'perl';
    my $info   = $_->{info};
    my $version = $info->{version} || '';
    print "checking for $module $version\n";

    eval "use $module $version"; ## no critic (Eval)
    next if ! $EVAL_ERROR;
    next if $info->{ships_with} && $info->{ships_with} eq 'perl';

    install_module( $module, $info, $version );
    eval "use $module $version"; ## no critic (Eval)
    if ($EVAL_ERROR) {
        push @failed, $module;
    }
}

if ( scalar @failed > 0 ) {
    print "The following modules failed installation:\n";
    print join( "\n", @failed );
    print "\n";
}

exit;

sub get_perl_modules {
    if ( -f 'dist.ini' ) {
        return get_perl_modules_from_ini();
    };
    if ( -f 'Makefile.PL' ) {
        return get_perl_modules_from_Makefile_PL();
    };
    die "unable to find module list. Run this script in the dist dir\n"; ## no critic (Carp)
}

sub get_perl_modules_from_Makefile_PL {
    my $fh = IO::File->new( 'Makefile.PL', 'r' )
        or die "unable to read Makefile.PL\n"; ## no critic (Carp)

    my $depth = 0;
    my @modules;
    while ( my $line = <$fh> ) {
        chomp $line;
        if ( $line =~ /"(PREREQ_PM|prereqs)"\s*=>\s*{/ ) {
            $depth++;
            # print "$depth: $line (" . scalar @modules . ")\n";
            next;
        }
        next if $depth < 1;
        if ($line =~ /(prereqs|configure|build|test|runtime|develop|requires|recommends|suggests).*{/){
            $depth++;
            # print "$depth: $line (" . scalar @modules . ")\n";
            next;
        }
        if ($line =~ /}/) {
            # print "$depth: $line (" . scalar @modules . ")\n";
            $depth--;
            last if $depth == 0;
            next;
        };
        if ($line !~ /=/) {  # no = char means not a module
            print "$line\n";
            next;
        }
        my ($mod, $ver) = split /\s*=\s*/, $line;
        $mod =~ s/[\s'"\#]*//xg; # strip whitespace & quotes ## no critic (Regex)
        next if ! $mod;
        push @modules, name_overrides($mod);
        # print "module: .$mod.\n";
    }
    $fh->close;
    return @modules;
}

sub get_perl_modules_from_ini {
    my $fh = IO::File->new( 'dist.ini', 'r' )
        or die "unable to read dist.ini\n"; ## no critic (Carp)

    my $in = 0;
    my @modules;
    while ( my $line = <$fh> ) {
        # install all prepreqs
        if ( '[Prereqs' eq substr($line,0,8) ) {
            # except for ones needed only by devs
            next if $line =~ /(?:BuildRequires|TestRequires)/i;
            $in++;
            next;
        };
        next if ! $in;
        # print "line: $line\n";
        next if ';' eq substr($line,0,1); # comment
        last if '[' eq substr($line,0,1); # [...] starts a new section
        my ($mod,$ver) = split /\s*=\s*/, $line;
        $mod =~ s/\s*//g;                 # remove whitespace
        next if ! $mod || ! defined $ver;
        push @modules, name_overrides($mod);
        print "module: $mod\n";
    }
    $fh->close;
    # print Dumper(\@modules);
    return @modules;
}

sub install_app {
    my ( $app, $info ) = @_;

    if ( lc($OSNAME) eq 'darwin' ) {
        install_app_darwin( $app, $info );
    }
    elsif ( lc($OSNAME) eq 'freebsd' ) {
        install_app_freebsd( $app, $info );
    }
    elsif ( lc($OSNAME) eq 'linux' ) {
        install_app_linux( $app, $info );
    };
    return;
}

sub install_app_darwin {
    my ($app, $info ) = @_;

    my $port = $info->{dport} || $info->{port} || $app;

    if ( ! -x '/opt/local/bin/port' ) {
        print "MacPorts is not installed! Consider installing it.\n";
        return;
    }

    system "/opt/local/bin/port install $port"
        and warn "install failed for Darwin port $port"; ## no critic (Carp)
    return;
}

sub install_app_freebsd {
    my ( $app, $info ) = @_;

    if ( -x '/usr/sbin/pkg' ) {
        if ( `/usr/sbin/pkg info -x $app` ) {  ## no critic (Backtick)
            return print "$app is installed.\n";
        }
        print "installing $app";
        return if install_app_freebsd_pkg($info, $app);
    }

    print " from ports...";

    if ( -x '/usr/sbin/pkg_info' ) {
        if ( `/usr/sbin/pkg_info | /usr/bin/grep $app` ) { ## no critic (Backtick)
            return print "$app is installed.\n";
        };
    }

    print "installing $app";
    return install_app_freebsd_port($app, $info);
}

sub install_app_freebsd_port {
    my ( $app, $info ) = @_;

    my $name = $info->{port} || $app;
    my $category = $info->{category} || '*';
    my ($portdir) = glob "/usr/ports/$category/$name"; ## no critic (Backtick)

    if ( $portdir && -d $portdir ) {
        print " from ports ($portdir)\n";
        system "make -C $portdir install clean" and do {
            warn "'make install clean' failed for port $app\n"; ## no critic (Carp)
        };
    };
    return;
}

sub install_app_freebsd_pkg {
    my ( $info, $app ) = @_;
    my $pkg = get_freebsd_pkgng() or return;
    my $name = $info->{port} || $app;
    print "installing $name\n";
    system "$pkg install -y $name";
    return 1 if is_freebsd_port_installed($name);

    return 0 if ($app eq $name);

    system "$pkg install -y $app";
    return 1 if is_freebsd_port_installed($app);
    return 0;
}

sub install_app_linux {
    my ($app, $info ) = @_;

    if ( -x '/usr/bin/yum' ) {
        my $rpm = $info->{yum} || $app;
        system "/usr/bin/yum -y install $rpm";
    }
    elsif ( -x '/usr/bin/apt-get' ) {
        my $package = lc($info->{apt} || $app);
        system "/usr/bin/apt-get -y install $package";
    }
    else {
        warn "no Linux package manager detected\n"; ## no critic (Carp)
    };
    return;
}

sub install_module {

    my ($module, $info, $version) = @_;

    if ( lc($OSNAME) eq 'darwin' ) {
        install_module_darwin($module, $info, $version);
    }
    elsif ( lc($OSNAME) eq 'freebsd' ) {
        install_module_freebsd($module, $info, $version);
    }
    elsif ( lc($OSNAME) eq 'linux' ) {
        install_module_linux( $module, $info, $version);
    };

    eval "require $module" or print ''; ## no critic (Stringy)
    return 1 if ! $EVAL_ERROR;

    install_module_cpan($module, $version);
    return;
}

sub install_module_cpan {

    my ($module, $version) = @_;

    print " from CPAN...";
    sleep 1;

    # this causes problems when CPAN is not configured.
    #local $ENV{PERL_MM_USE_DEFAULT} = 1; # supress CPAN prompts

    local $ENV{FTP_PASSIVE} = 1;          # for FTP behind NAT/firewalls

    # some Linux distros break CPAN by auto/preconfiguring it with no URL mirrors.
    # this works around that annoying little habit
    $CPAN::Config = get_cpan_config(); ## no critic (PackageVars)

    # a hack to grab the latest version on CPAN before its hits the mirrors
    if ( $module eq 'Provision::Unix' && $version ) {
        $module =~ s/\:\:/\-/g;
        $module = "M/MS/MSIMERSON/$module-$version.tar.gz";
    }
    CPAN::Shell->install($module);  ## no critic (PackageVars)
    return;
}

sub install_module_darwin {
    my ($module, $info, $version) = @_;

    my $dport = '/opt/local/bin/port';
    if ( ! -x $dport ) {
        print "MacPorts is not installed! Consider installing it.\n";
        return;
    }

    my $port = "p5-$module";
    $port =~ s/::/-/g;
    system "$dport install $port"
        and warn "install failed for Darwin port $module"; ## no critic (Carp)
    return;
}

sub install_module_freebsd {
    my ($module, $info, $version) = @_;

    my $name = $info->{port} || $module;
    my $portname = substr($name, 0, 3) eq 'p5-' ? $name : "p5-$name";
    $portname =~ s/::/-/g;

    if (is_freebsd_port_installed($portname)) {
        return print "$module is installed.\n";
    };
    return 1 if install_module_freebsd_pkg($portname);
    return install_module_freebsd_port($portname, $info, $module);
}

sub install_module_freebsd_port {
    my ($portname, $info, $module) = @_;
    print " from ports...$portname...";

    if (is_freebsd_port_installed($module, $portname)) {
        return print "$module is installed.\n";
    }

    print "installing $module ...";

    my $category = $info->{category} || '*';
    my ($portdir) = glob "/usr/ports/$category/$portname";

    if ( ! $portdir || ! -d $portdir ) {
        print "no match at /usr/ports/$category/$portname\n";
        return;
    };

    print " from ports ($portdir)\n";
    system "make -C $portdir install clean"
        and warn "'make install clean' failed for port $module\n"; ## no critic (Carp)
    return;
}

sub install_module_freebsd_pkg {
    my ( $module ) = @_;
    my $pkg = get_freebsd_pkgng() or return 0;
    print "installing $module\n";
    system "$pkg install -y $module";
    return is_freebsd_port_installed($module);
}

sub is_freebsd_port_installed {
    my ( $module, $portname ) = @_;

    my $pkg = get_freebsd_pkgng();
    if ($pkg) {
        return 1 if `$pkg info -x $module`;  ## no critic (Backtick)
    }

    my $pkg_info = get_freebsd_pkgng();
    if ($pkg_info) {
        $portname ||= $module;
        if ( `$pkg_info | /usr/bin/grep $portname` ) { ## no critic (Backtick)
            return print "$module is installed.\n";
        }
    }

    return 0;
}

sub get_freebsd_pkgng {
    my $pkg = '/usr/local/sbin/pkg';  # port version is likely newest
    if (! -x $pkg) { $pkg = '/usr/sbin/pkg'; };  # fall back
    if (! -x $pkg) {
        warn "pkg not installed!\n";
        return 0;
    }
    return $pkg;
}

sub install_module_linux {
    my ($module, $info, $version) = @_;

    my $package;
    if ( -x '/usr/bin/yum' ) { ## no critic (Backtick)
        return install_module_linux_yum($module, $info);
    }
    elsif ( -x '/usr/bin/apt-get' ) { ## no critic (Backtick)
        return install_module_linux_apt($module, $info);
    }
    warn "no Linux package manager detected\n"; ## no critic (Carp)
    return;
}

sub install_module_linux_yum {
    my ($module, $info) = @_;
    my $package;
    if ( $info->{yum} ) {
        $package = $info->{yum};
    }
    else {
        $package = "perl-$module";
        $package =~ s/::/-/g;
    };
    system "/usr/bin/yum -y install $package";
    return;
}

sub install_module_linux_apt {
    my ($module, $info) = @_;
    my $package;
    if ( $info->{apt} ) {
        $package = $info->{apt};
    }
    else {
        $package = 'lib' . lc $module . '-perl';
        $package =~ s/::/-/g;
    };
    system "/usr/bin/apt-get -y install $package";
    return;
}

sub get_cpan_config {

    my $ftp = `which ftp`; chomp $ftp;  ## no critic (Backtick)
    my $gzip = `which gzip`; chomp $gzip; ## no critic (Backtick)
    my $unzip = `which unzip`; chomp $unzip; ## no critic (Backtick)
    my $tar  = `which tar`; chomp $tar; ## no critic (Backtick)
    my $make = `which make`; chomp $make; ## no critic (Backtick)
    my $wget = `which wget`; chomp $wget; ## no critic (Backtick)

    return {
        'build_cache' => q[10],
        'build_dir' => qq[$ENV{HOME}/.cpan/build],
        'cache_metadata' => q[1],
        'cpan_home' => qq[$ENV{HOME}/.cpan],
        'ftp' => $ftp,
        'ftp_proxy' => q[],
        'getcwd' => q[cwd],
        'gpg' => q[],
        'gzip' => $gzip,
        'histfile' => qq[$ENV{HOME}/.cpan/histfile],
        'histsize' => q[100],
        'http_proxy' => q[],
        'inactivity_timeout' => q[5],
        'index_expire' => q[1],
        'inhibit_startup_message' => q[1],
        'keep_source_where' => qq[$ENV{HOME}/.cpan/sources],
        'lynx' => q[],
        'make' => $make,
        'make_arg' => q[],
        'make_install_arg' => q[],
        'makepl_arg' => q[],
        'ncftp' => q[],
        'ncftpget' => q[],
        'no_proxy' => q[],
        'pager' => q[less],
        'prerequisites_policy' => q[follow],
        'scan_cache' => q[atstart],
        'shell' => q[/bin/csh],
        'tar' => $tar,
        'term_is_latin' => q[1],
        'unzip' => $unzip,
        'urllist' => [ 'http://www.perl.com/CPAN/', 'http://mirrors.kernel.org/pub/CPAN/',
          'ftp://cpan.cs.utah.edu/pub/CPAN/', 'ftp://mirrors.kernel.org/pub/CPAN',
          'ftp://osl.uoregon.edu/CPAN/', 'http://cpan.yahoo.com/',
          'ftp://ftp.funet.fi/pub/languages/perl/CPAN/'
        ],
        'wget' => $wget,
    };
}

sub name_overrides {
    my $mod = shift;
    # Package and port managers have naming conventions for perl modules. The
    # methods will typically work out the name based on the module name and a
    # couple rules. When that doesn't work, add entries here for FreeBSD (port),
    # MacPorts ($dport), yum, and apt.
    my @modules = (
        { module=>'LWP::UserAgent'    , info => { cat=>'www', port=>'p5-libwww', dport=>'p5-libwww-perl', yum=>'perl-libwww-perl' }, },
        { module=>'Mail::Send'        , info => { port => 'Mail::Tools', }  },
        { module=>'Date::Parse'       , info => { port => 'TimeDate',    }  },
        { module=>'LWP'               , info => { port => 'p5-libwww',   }  },
        { module=>'Net::DNS::Resolver', info => { apt => 'libnet-dns-perl',     }  },
        { module=>'DBD::SQLite'       , info => { apt => 'libdbd-sqlite3-perl', }  },
    );
    my ($match) = grep { $_->{module} eq $mod } @modules;
    return $match if $match;
    return { module=>$mod, info => { } };
}

__END__

=pod

=head1 NAME

install_deps.pl: install dependencies with package manager or CPAN

=head1 AUTHORS

=over 4

=item *

Matt Simerson <msimerson@cpan.org>

=back

=cut
