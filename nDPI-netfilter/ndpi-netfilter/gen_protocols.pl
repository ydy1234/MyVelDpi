#!/usr/bin/perl -w
use English;

my @P;
my %N;
my @L;
my $m=0;
my ($t,$n,$p);
die "$PROGRAM_NAME dstfile src.h .h.src\n" 
  if !defined $ARGV[0] || !defined $ARGV[1] || !defined $ARGV[2] ||
 ! -f $ARGV[1] || ! -f $ARGV[2];

die "BUG1" if !open(F,'<'.$ARGV[1]);

while(<F>) {
	next if !/^\s*#define\s+NDPI_(CONTENT|SERVICE|PROTOCOL)_(\S+)\s+(\d+)(\s+|$)/;
	next if $2 eq "HISTORY_SIZE";
	($t,$p,$n) = ($1,$2,$3);
#	print "$p $n\n";
	die "BUG! $p ($n) redefined $P[$n]" if defined $P[$n];
	$P[$n]=$p;
	$N{$p}=$n;
	$L[$n] = 'NDPI_'.$t.'_'.$p;
	$m = $n if $n > $m;
}
close(F);
if(defined $ARGV[3]) {
	die "BUG4" if !open(F,'>'.$ARGV[3]);
	for($n=0; $n <= $m; $n++) {
		print F "_P($L[$n]),\n";
	}
	close(F);
}
@L=(0,0,0,0,0,0);
for($n=0; $n <= $m; $n++) {
	$i = !$n ? 0 : ($n % 5);
	$p = defined $P[$n] ? lc($P[$n]):"badproto_${n}";
	$p =~ s/http_application_/http_app_/;
	$P[$n] = $p;
	$p = length($p);
	$L[$i] = $p if $p > $L[$i];
}
die "BUG2" if !open(F,'<'.$ARGV[2]);
die "BUG3" if !open(O,'>'.$ARGV[0]);
print O "/*  Don't edit this file! Source file $ARGV[2] */\n\n";
while(<F>) {
	if(!/__SUB__/) {
		print O $_;;
		next;
	}
	print O "#define NDPI_PROTOCOL_SHORT_STRING \"unknown\",	";
	for($n=1; $n <= $m; $n++) {
		$i = !$n ? 0 : ($n % 5);
		$s = '"'.$P[$n].'"';
		if($n == $m) {
			$s .= "\n";
		} else {
			$s .= "," . ($i ? sprintf("%.*s",$L[$i]+3-length($s),"                   "):"\\\n");
		}

		print O $s;
	}
	print O "#define NDPI_PROTOCOL_MAXNUM $m\n";
}
close(O);
close(F);
exit(0);
