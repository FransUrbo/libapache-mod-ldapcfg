my $dir;
my %a;

while( <STDIN> )
{
    if( m|<h2>| )
    {
        while( ! m|</h2>| )
        {
            chomp;
            $_ .= <STDIN>;
        }

        if( m|">(.+?) directive</a>| ||
            m|">(.+?)</a>| )
        {
            $dir = $1;
            $dir =~ s/&lt;/\</;
            $dir =~ s/&gt;/\>/;
            $dir =~ s/\s//g;
        }
    }
    elsif( m|Syntax:| )
    {
        while( ! m/<br \// )
        {
            chomp;
            $_ .= <STDIN>;
        }

        if( m|</a>(.*?)<br />| )
        {
            $a{ $dir } = $1;
            $a{ $dir } =~ s|\s+| |g;
            $a{ $dir } =~ s|^\s+||;
            $a{ $dir } =~ s|</*em>||g;
            $a{ $dir } =~ s/&lt;/\</;
            $a{ $dir } =~ s/&gt;/\>/;
        }
        else
        {
            print "ERROR: $dir\n";
        }
    }
}

print map( "$_ = $a{ $_ }\n", sort keys %a );
