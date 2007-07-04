my %secs;

while( <STDIN> )
{
    chomp;
    if( m|^(\w+) = (.*)$| )
    {
        my $dir = $1;
        my $sec = $2;
        $sec =~ s/\s//g;
        for( split( ',', $sec ) )
        {
            push( @{ $secs{ $_ } }, $dir );
        }
    }
}
# Print by Section
print map( "[$_]\n" . join( "\n", sort @{ $secs{ $_ } } ) . "\n\n", sort keys %secs );
