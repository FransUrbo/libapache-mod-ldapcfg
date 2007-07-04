#!/usr/bin/perl -w

my $syntax_file = 'syntax.txt';
my $direct_file = 'directives.txt';

# Assigned numbers
my $base_oid = '1.3.6.1.4.1.13607';
# $base_oid.[Individuals].[Brian Ferris].[ApacheLDAPConfig]
my $sub_oid = "$base_oid.1.1.1";

my $obj_oid = "$sub_oid.1";
my $attr_oid = "$sub_oid.2";

my $obj_prefix = 'Apache';
my $attr_prefix = 'Apache';

my $obj_index = 1;
my $attr_index = 1;

my $ascii_attr =
qq(\tEQUALITY caseExactIA5Match
\tSUBSTR caseExactIA5SubstringsMatch
\tSYNTAX 1.3.6.1.4.1.1466.115.121.1.26);

my $int_attr =
qq(\tEQUALITY integerMatch
\tSYNTAX 1.3.6.1.4.1.1466.115.121.1.27);

my %syntax;

open( SYNTAX, $syntax_file ) or die "Can't open $syntax_file: $!";

while( <SYNTAX> )
{
    chomp;
    if( m|^(\w+) = (.*)$| )
    {
        $syntax{ $1 } = $2;
    }
}

close( SYNTAX );

open( DIRECT, $direct_file ) or die "Can't open $direct_file: $!";

my $current_obj;
my %all_attrs;
my %oids;

while( <DIRECT> )
{
    chomp;

    if( m|^\[(.+)\]$| )
    {
        my ( $obj, $parent ) = split( ':', $1 );

        if( $current_obj )
        {
            my $name = $current_obj->{ name };
            $name =~ s/_(\w)/\u$1/g;
            $name =~ s/^(\w)/\u$1/;

            my $oid = $obj_oid . "." . $obj_index++;
            my $obj_text = "objectclass ( $oid NAME '" . $obj_prefix . $name . "Obj'\n" .
            "\tDESC 'Contains configuration directives for $current_obj->{ name }'\n";

            if( $current_obj->{ parent } )
            {
                my $parent = $current_obj->{ parent };
                $parent =~ s/(^|_)(\w)/\u$2/g;

                $obj_text .= "\tSUP '" . $obj_prefix . $parent . "Obj'\n";
            }

            if( scalar @{ $current_obj->{ attrs } } > 1 )
            {
                my $attrs = join( ' $ ', map( "$attr_prefix$_", @{ $current_obj->{ attrs } } ) );
                $attrs =~ s|(([^\$]+\$){3})|$1\n\t\t|g;
                $obj_text .= "\tMAY ( $attrs )";
            }
            else
            {
                $obj_text .= "\tMAY $attr_prefix$current_obj->{ attrs }->[0]";
            }

            print "$obj_text )" . "\n" x 2 . "#" x 20 . "\n" x 2;
        }

        $current_obj =
        {
         name => $obj,
         attrs => []
        };

        if( $parent )
        {
            $current_obj->{ parent } = $parent;
        }

    }
    elsif( m|^(\w+)\s*(.*)$| )
    {
        my $name = $1;
        my $type = $2;

        my $orig_name = $name;

        # You can't use a '_' character in an attribute name
        $name =~ s|_|--|g;

        push( @{ $current_obj->{ attrs } }, $name );

        unless( exists( $all_attrs{ $name } ) )
        {
            $all_attrs{ $name }++;

            my $oid = "$attr_oid." . $attr_index++;
         
            exists( $syntax{ $orig_name } ) or die "Can't find syntax for $name\n";

            my $attr_text = "attributetype ( $oid NAME '$attr_prefix$name'\n" .
                            "\tDESC 'Syntax: $syntax{ $orig_name }'\n";

            $attr_text .= ( $type =~ m|\[int\]| ) ? $int_attr : $ascii_attr;
            $attr_text .= ( $type =~ m|\[m\]| ) ? '' : ' SINGLE-VALUE';

            $attr_text .= " )\n\n";

            print $attr_text;

        }
    }
}
