# sting
sting is a matching module with the specific purpose to deterministically 
respond to a TCP connection for the purpose of identifying the real IP 
address(es) of an attacker. It will filter through incoming packets and 
allows certain packets to advance down the chain, determined using entropy,
to targets father down the chain.

## Building
### Prerequisites
To build sting (and all of the other xtables-addons modules), you must first
make sure you have the libxt headers installed.  This will look different
depending on which distro the target machine is running, but the
`iptables-devel` package often contains those.

### Configuring the Build System
Once you have the headers on your machine, you must run the `autogen.sh` script
to generate the configuration files. Then you must run the `configure` script
to generate the makefiles. Configure will validate that you have the proper
tools and headers on your system to proceed. If configure fails, then you must
install whatever packages it's asking for.

### Compiling the Modules
At this point, you're ready to start building the code itself. Per convention,
`make` is all that needs to be run to build all the modules. You may want to
run `make -jn` where `n` is the number of available cores on your machine.
This will speed up the build by using all of the cores instead of `make`'s
default of a single core.

## Installing
Again, per convention, `make install` will install the modules and
documentation. This must be run as root (by using `sudo` or some other means)
because it installs files into system directories.

## Running
Since xtables-addons (and by extension sting) are extensions to iptables, all
you need to get sting up and running is to run an `iptables` with a `-j
sting` followed by the sting options. For details on how to configure the
sting extension, see the man page for `xtables-addons` which will be
installed to your system when you run `make install`.

## Testing
The `bin` directory contains several scripts to aid in rapid iteration of
development and testing. For details on how to use each of the scripts, see the
README in `bin`.

