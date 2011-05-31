Homework
========

[Homework][] is a research project involving University of
Nottingham's MRL, University of Glasgow, Imperial College, Georgia
Institute of Technology, Microsoft Research Cambridge and BT.  The
code here is a repository and distribution of some implementation
attempts at a controllable Homework router utilising NoX/Openflow
(specifically OpenVSwitch).  Homework specific code is licensed under
AGPLv3; core NoX and OpenVSwitch code is licensed as noted therein.

[homework]: http://www.homenetworks.ac.uk/

Obtaining Code
--------------

The repository is structured using `git` *submodules*.  See the `git`
documentation for details; in short they are a way to include by
reference other repositories within your own.  As a result, obtaining
the complete set of code is a two-stage process:

    $ git clone git://github.com/homework/homework.git
    $ cd homework
    $ git submodule init && git submodule update

This will give you scripts and documentation associated with this
implementation, plus an occasionally updated clone of the
[Open vSwitch git repository][ovs-home] and the `homework` NoX
controller itself on embedded within a local branch of the
occasionally updated [NoX git repository][nox-home].

[ovs-home]: http://openvswitch.org/
[nox-home]: http://noxrepo.org/

Build and install has been tested on eeePCs running Ubuntu 10.x.  See
<http://www.dcs.gla.ac.uk/~koliousa/hr.html> for more detail.  Build
and install requires the following packages:

    $ sudo apt-get install autoconf automake libtool pkg-config g++ python \
           python-dev python-twisted swig libxerces-c2-dev libssl-dev make \
           libsqlite3-dev python-simplejson python-sphinx libboost1.40-dev \
           libboost-filesystem1.40-dev libboost-test1.40-dev curl

Subsequent instructions assume `ROOT` is set to the directory into
which you cloned this repository.

Building Open vSwitch
---------------------

Follow the build and install instructions as given; in short:

    $ cd ${ROOT}/openvswitch.git/
    $ ./boot.sh
    $ ./configure --with-l26=/lib/modules/`uname -r`/build
    $ make -j4 ; make
    $ sudo make install

Building NoX
------------

    $ cd ${ROOT}/nox.git/
    $ ./boot.sh
    $ mkdir build && cd build && ../configure
    $ make -j4 ; make
    $ cd src && make check
    $ cd etc && for n in noxca.key* ; do mv $n ${n}.disabled ; done


Starting the Homework Router
============================

Having configured the eeePC as specified at
<http://www.dcs.gla.ac.uk/~koliousa/hr.html>, and having obtained,
built and installed the code as specified above, the following
describes how to actually run things and control the Homework router.

Steps (2) -- (4) will each startup processes that take control of the
terminal, ie., will need running in separate terminals.  If you want,
investigate the man pages for `ovsdb-server` and `ovs-vswitchd` to see
how to run then as background daemons.

Steps (2), (5) need only be carried out once, or whenever the eeePC
network configuration changes.

(1) Replace the bridge module with the openvswitch equivalents (datapath)

    $ cd ${ROOT}
    $ sudo rmmod bridge
    $ sudo insmod ./openvswitch.git/datapath/linux-2.6/openvswitch_mod.ko 
    $ sudo insmod ./openvswitch.git/datapath/linux-2.6/brcompat_mod.ko 

(2) Create `ovsdb.conf` file if it doesn't exist

    $ cd openvswitch.git
    $ ovsdb-tool create ovsdb.conf vswitchd/vswitch.ovsschema
    
(3) Start `ovsdb-server`

    $ cd ${ROOT}/openvswitch.git
    $ sudo ovsdb-server ovsdb.conf --remote=punix:/var/run/ovsdb-server

(4) Start `ovs-vswitchd`, the secure channel between datapath and controller

    $ sudo ovs-vswitchd unix:/var/run/ovsdb-server 

(5) Initialise the database, create the bridge, &c

    $ sudo ovs-vsctl --db=unix:/var/run/ovsdb-server init
    $ sudo ovs-vsctl --db=unix:/var/run/ovsdb-server add-br br0
    $ sudo ovs-vsctl --db=unix:/var/run/ovsdb-server set-fail-mode br0 secure
    $ sudo ovs-vsctl --db=unix:/var/run/ovsdb-server set-controller br0 tcp:127.0.0.1:6633
    $ sudo ovs-vsctl --db=unix:/var/run/ovsdb-server add-port br0 wlan1

(6) Start NoX (the controller), specifying the homework script

    $ cd ${ROOT}/nox.git/build/src
    $ sudo ./nox_core -v -i ptcp:localhost homework

(7) Restart hostapd since it seems to get confused pretty much every time

    $ sudo /etc/init.d/hostapd restart

(8) Permit a mac address to do anything; eaddr=xx:xx:xx:xx:xx:xx

    $ curl --noproxy localhost -X POST http://localhost/ws.v1/homework/permit/<eaddr>


Interrogation
-------------

Permit/deny status of Homework router

    $ curl --noproxy localhost -X GET http://localhost/ws.v1/homework/status 

To see what flows have been installed in openvswitch

    $ ovs-ofctl dump-flows dp0

To see what flows are really installed in the datapath; differs from
above as include transient flows based on observed packets, while
installed flows are the actual permitted entries

    $ ovs-dpctl dump-flows dp0

