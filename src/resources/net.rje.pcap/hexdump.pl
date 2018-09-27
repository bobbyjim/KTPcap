#!/usr/bin/perl

$|=1;

my $file   = shift || die "SYNOPSIS: $0 image-name block-offset length\n";
my $offset = shift || 0;
my $length = shift || 0;
my $buffer;
my $rv;

open IN, $file;
binmode IN;
$rv = read(IN, $buffer, -s $file)
        or die "Couldn't read from IN : $!\n";
close IN;

my @var = unpack 'C*', $buffer;

if ( $offset )
{
   @var = @var[ $offset * 256 .. $#var ];
   print scalar @var, " bytes\n";
   if ( $length )
   {
      @var = @var[ 0 .. 256 * $length ];
      print scalar @var, " bytes\n";
   }
}

my $instring = 0;
for( my $i=0; $i<@var; $i+=16 )
{
   my $str = '';
   my $mask = '';
   for ($i..$i+15) 
   {
      my $c = $var[$_];

      select undef, undef, undef, 0.001 if $c > 0; # slightly slower

      if ($c >= 0x20 && $c < 0x7f)
      {
        $mask .= 'C';
        $inString = 1;
        $str  .= (sprintf "%c", $c);
        select undef, undef, undef, 0.01; # pause a bit longer
      }
      elsif ($c == 0xa0 && $inString == 1 )
      {
        $mask .= '-';
		$str  .= '.';
      }
      else
      {
         $mask    .= '.';
		 $str     .= '.';
         $inString = 0;
      }
   }
   printf "%05x:  %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x  $str  $mask\n", $i+$offset*256, @var[$i..$i+16];
}
