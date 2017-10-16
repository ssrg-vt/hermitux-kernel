#!/bin/sh

ISLE=qemu
KVM=1

HERMIT_ISLE=$ISLE HERMIT_KVM=$KVM ./prefix/bin/proxy \
	prefix/x86_64-hermit/extra/tests/gettimeofday
