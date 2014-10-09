novena-disable-ssp
==================

Bluetooth devices support something called SSP -- "Simple Secure Pairing",
or something like that.  It encrypts keys, or does some sort of exchange,
or does rotation... I'm not really sure what it does.

I do know that it makes it very inconvenient for using Bluetooth keyboards,
as they tend to not want to reassociate.

This program will monitor all Bluetooth adapters and disable SSP on them
when it sees them.

This may be due to a bug in the adapter, where different USB endpoints
mean that encrpytion data can be broadcast out-of-order.  A patch was
submitted to Linux in 2011, but no action was taken.


Building
--------

To build the Debian package, check out the code and use git-buildpackage.
Note that this script will output the resulting packages into the directory
above the current one.  Specify a tag with --git-upstream-tag, and possibly
-us -uc.  E.g.:

    git-buildpackage -us -uc --git-upstream-tag=v1.0
