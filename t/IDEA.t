#!/usr/local/bin/perl

use lib '..','../blib/lib','.','./blib/lib';

eval "use Crypt::IDEA()";
if ($@) {
    warn "Crypt::IDEA not installed\n";
    print "1..0\n";
    exit;
}

print "1..5\n";

sub test {
    local($^W) = 0;
    my($num, $true,$msg) = @_;
    print($true ? "ok $num\n" : "not ok $num $msg\n");
}

$test_data = <<END;
Mary had a little lamb,
Its fleece was black as coal,
And everywere that Mary went,
That lamb would dig a hole.
END
    ;

eval "use Crypt::CBC";

test(1,!$@,"Couldn't load module");
test(2,$i = Crypt::CBC->new('secret','IDEA'),"Couldn't create new object");
test(3,$c = $i->encrypt($test_data),"Couldn't encrypt");
test(4,$p = $i->decrypt($c),"Couldn't decrypt");
test(5,$p eq $test_data,"Decrypted ciphertext doesn't match plaintext");
