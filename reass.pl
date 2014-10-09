#!/usr/bin/perl
use strict;
use Regexp::Assemble;
 
my $ra = Regexp::Assemble->new;
while (<>)
{
  $ra->add($_);
}
print $ra->as_string() . "\n"; 
