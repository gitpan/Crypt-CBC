package Crypt::CBC;

use MD5;
use Carp;
use strict;
use vars qw($VERSION);
$VERSION = '1.22';

sub new ($$;$) {
    my $class = shift;
    my ($key,$cipher) = @_;
    croak "Please provide an encryption/decryption key" unless defined $key;
    $cipher = 'Crypt::DES' unless $cipher;
    $cipher = $cipher=~/^Crypt::/ ? $cipher : "Crypt::$cipher";
    eval "require $cipher";
    croak "Couldn't load $cipher: $@" if $@;

    # some crypt modules use the class Crypt::, and others don't
    $cipher =~ s/^Crypt::// unless $cipher->can('keysize');
    my $ks = $cipher->keysize;
    my $bs = $cipher->blocksize;

    # Some of the cipher modules are busted and don't report the
    # keysize (well, Crypt::Blowfish in any case).  If we detect
    # this, and find the blowfish module in use, then assume 56.
    # Otherwise assume the least common denominator of 8.
    $ks = $cipher =~ /blowfish/i ? 56 : 8 unless $ks > 0;

    # the real key is computed from the first N bytes of the
    # MD5 hash of the provided key.
    my $material = MD5->hash($key);
    while (length($material) < $ks + $bs)  {
	$material .= MD5->hash($material);
    }
	
    # Original implementation of SSLEay used part of the key for the IV
    # which is not a good idea.  The decryption iv is taken from
    # the second byte of the file if present, tossing the one stored
    # here.
    my ($k,$iv) = $material =~ /(.{$ks})(.{$bs})/os;

    return bless {'crypt' => $cipher->new($k),
		  'iv'    => $iv
		  },$class;
}

sub encrypt (\$$) {
    my ($self,$data) = @_;
    $self->start('encrypting');
    my $result = $self->crypt($data);
    $result .= $self->finish;
    $result;
}

sub decrypt (\$$){
    my ($self,$data) = @_;
    $self->start('decrypting');
    my $result = $self->crypt($data);
    $result .= $self->finish;
    $result;
}

sub encrypt_hex (\$$) {
    my ($self,$data) = @_;
    return join('',unpack 'H*',$self->encrypt($data));
}

sub decrypt_hex (\$$) {
    my ($self,$data) = @_;
    return $self->decrypt(pack'H*',$data);
}

# call to start a series of encryption/decryption operations
sub start (\$$) {
    my $self = shift;
    my $operation = shift;
    croak "Specify <e>ncryption or <d>ecryption" 
	unless $operation=~/^[ed]/i;
    $self->{'buffer'} = '';
    $self->{'decrypt'} = $operation=~/^d/i;
}

# call to encrypt/decrypt a bit of data
sub crypt (\$$){
    my $self = shift;
    my $data = shift;
    croak "crypt() called without a preceding start()"
      unless exists $self->{'buffer'};
    
    my $result = '';

    if ( !$self->{'civ'} ) {
      if ($self->{'decrypt'}) {
	if (my ($iv) = $data=~ /^RandomIV(.{8})/s) {
	  $self->{'iv'} = $iv;
	  substr($data,0,16) = ''; #truncate
	}
      } else { # encrypting
	$self->{'iv'} = pack("C*",map {rand(255)} 1..8);
	$result = 'RandomIV';
	$result .= $self->{'iv'};
      }
      $self->{'civ'} = $self->{'iv'};
    }

    $self->{'buffer'} .= $data;
    my $iv = $self->{'civ'};
    my $bs = $self->{'crypt'}->blocksize;
    my $d = $self->{'decrypt'};

    return $result unless length($self->{'buffer'}) >= $bs;
    my @blocks = $self->{'buffer'}=~/(.{1,$bs})/ogs;

    $self->{'buffer'} = '';
    if ($d) {  # when decrypting, always leave a free block at the end
	$self->{'buffer'} = length($blocks[-1]) < $bs ? join '',splice(@blocks,-2) : pop(@blocks);
    } else {
	$self->{'buffer'} = pop @blocks if length($blocks[-1]) < $bs;  # what's left over
    }

    foreach my $block (@blocks) {
	if ($d) { # decrypting
	    $result .= $iv ^ $self->{'crypt'}->decrypt($block);
	    $iv = $block;
	} else { # encrypting
	    $result .= $iv = $self->{'crypt'}->encrypt($iv ^ $block);
	}
    }
    $self->{'civ'} = $iv;	        # remember the iv
    return $result;
}

# this is called at the end to flush whatever's left
sub finish (\$) {
    my $self = shift;
    my $bs = $self->{'crypt'}->blocksize;
    my $block = $self->{'buffer'};

   $self->{civ} ||= '';
    
    my $result;
    if ($self->{'decrypt'}) { #decrypting	
	$block = pack("a$bs",$block); # pad and truncate to block size
	if (length($block)) {	
		$result = $self->{'civ'} ^ $self->{'crypt'}->decrypt($block);
		substr($result,-unpack("C",substr($result,-1)))='';	
	} else {
		$result = '';
	}
    } else { # encrypting
	# in case we had an even multiple of bs
	$block = pack("C*",($bs)x$bs) unless length($block);  
	if (length($block)) {

		$block .= pack("C*",($bs-length($block)) x ($bs-length($block))) 
		    if length($block) < $bs;
		$result = $self->{'crypt'}->encrypt($self->{'civ'} ^ $block);	
	} else {
		$result = '';
	}
    }
    delete $self->{'civ'};
    delete $self->{'buffer'};
    return $result;
}

1;
__END__

=head1 NAME

Crypt::CBC - Encrypt Data with Cipher Block Chaining Mode

=head1 SYNOPSIS

  use Crypt::CBC;
  $cipher = new Crypt::CBC('my secret key','IDEA');
  $ciphertext = $cipher->encrypt("This data is hush hush");
  $plaintext = $cipher->decrypt($ciphertext);

  $cipher->start('encrypting');
  open(F,"./BIG_FILE");
  while (read(F,$buffer,1024)) {
      print $cipher->crypt($buffer);
  }
  print $cipher->finish;


=head1 DESCRIPTION

This module is a Perl-only implementation of the cryptographic cipher
block chaining mode (CBC).  In combination with a block cipher such as
DES or IDEA, you can encrypt and decrypt messages of arbitrarily long
length.  The encrypted messages are compatible with the encryption
format used by B<SSLeay>.

To use this module, you will first create a new Crypt::CBC cipher object with
new().  At the time of cipher creation, you specify an encryption key
to use and, optionally, a block encryption algorithm.  You will then
call the start() method to initialize the encryption or decryption
process, crypt() to encrypt or decrypt one or more blocks of data, and
lastly finish(), to flush the encryption stream.  For your
convenience, you can call the encrypt() and decrypt() methods to
operate on a whole data value at once.

=head2 new()

  $cipher = new Crypt::CBC($key,$algorithm);

The new() method creates a new Crypt::CBC object.  

You must provide an encryption/decryption key, which can be any series
of characters of any length.  Internally, the actual key used is
derived from the MD5 hash of the key you provide.  The optional second
argument is the block encryption algorithm to use, specified as a
package name.  You may use any block encryption algorithm that you
have installed.  At the time this was written, only two were available
on CPAN, Crypt::DES and Crypt::IDEA.  You may refer to them using
their full names ("Crypt::IDEA") or in abbreviated form ("IDEA".)  If
no algorithm is provided, DES is assumed.

=head2 start()

   $cipher->start('encrypting');
   $cipher->start('decrypting');

The start() method prepares the cipher for a series of encryption or
decryption steps, resetting the internal state of the cipher if
necessary.  You must provide a string indicating whether you wish to
encrypt or decrypt.  "E" or any word that begins with an "e" indicates
encryption.  "D" or any word that begins with a "d" indicates
decryption.

=head2 crypt()
 
   $ciphertext = $cipher->crypt($plaintext);

After calling start(), you should call crypt() as many times as
necessary to encrypt the desired data.  

=head2  finish()

   $ciphertext = $cipher->finish();

The CBC algorithm must buffer data blocks inernally until they are
even multiples of the encryption algorithm's blocksize (typically 8
bytes).  After the last call to crypt() you should call finish().
This flushes the internal buffer and returns any leftover ciphertext.

In a typical application you will read the plaintext from a file or
input stream and write the result to standard output in a loop that
might look like this:

  $cipher = new Crypt::CBC('hey jude!');
  $cipher->start('encrypting');
  print $cipher->crypt($_) while <>;
  print $cipher->finish();

=head2 encrypt()

  $ciphertext = $cipher->encrypt($plaintext)

This convenience function runs the entire sequence of start(), crypt()
and finish() for you, processing the provided plaintext and returning
the corresponding ciphertext.

=head2 decrypt()

  $plaintext = $cipher->decrypt($ciphertext)

This convenience function runs the entire sequence of start(), crypt()
and finish() for you, processing the provided ciphertext and returning
the corresponding plaintext.

=head2 encrypt_hex(), decrypt_hex()

  $ciphertext = $cipher->encrypt_hex($plaintext)
  $plaintext  = $cipher->decrypt_hex($ciphertext)

These are convenience functions that operate on ciphertext in a
hexadecimal representation.  B<encrypt_hex($plaintext)> is exactly
equivalent to B<unpack('H*',encrypt($plaintext))>.  These functions
can be useful if, for example, you wish to place the encrypted
information into an e-mail message, Web page or URL.

=head1 EXAMPLES

Two examples, des.pl and idea.pl can be found in the eg/ subdirectory
of the Crypt-CBC distribution.  These implement command-line DES and
IDEA encryption algorithms.

=head1 LIMITATIONS

The encryption and decryption process is about a tenth the speed of
the equivalent SSLeay programs (compiled C).  This could be improved
by implementing this module in C.  It may also be worthwhile to
optimize the DES and IDEA block algorithms further.

=head1 BUGS

None that I know of.

=head1 AUTHOR

Lincoln Stein, lstein@cshl.org

=head1 SEE ALSO

perl(1), Crypt::DES(3), Crypt::IDEA(3)

=cut
