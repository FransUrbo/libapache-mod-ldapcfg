while( <STDIN> )
{
    if( m|<li>| )
    {
        while( ! m|</li>| )
        {
            chomp;
            $_ .= <STDIN>;
        }
        # print "Trying: $_";

        m|href="(\w+)|;
        my $mod = $1;
        m|">(.+)</a>|;
        my $dir = $1;
        $dir =~ s|&lt;|<|;
        $dir =~ s|&gt;|>|;
        push( @{ $a{ $mod } }, $dir);
    }
}

print map( "[$_]\n" . join( "\n", sort @{ $a{ $_ } } ) . "\n\n", sort keys %a );
