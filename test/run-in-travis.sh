#!/bin/sh

unit_tests() {
	echo "** Unit tests"
	./test/run
}

configure() {
	echo "** Autogen / Configure"
	./autogen.sh
	./configure --prefix /usr
}

make_install() {
	echo "** Make / Install"
	make install
}

regression_tests() {
	echo "** Regression tests"
	sh /usr/share/crmsh/tests/regression.sh
}

qdevice_tests() {
	echo "** Qdevice/Qnetd tests"
	behave --no-capture --no-capture-stderr /usr/share/crmsh/tests/features
}

if [ "$1" = "" ];then
  unit_tests
  rc_unittest=$?
fi
configure
make_install
if [ "$1" = "" ]; then
  regression_tests && exit $rc_unittest
elif [ "$1" = "qdevice" ];then
  qdevice_tests && exit 0
fi
