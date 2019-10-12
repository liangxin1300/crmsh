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

bootstrap_tests() {
	echo "** Bootstrap process tests"
        behave --no-capture --no-capture-stderr /usr/share/crmsh/tests/features
}

case "$1" in
	build)
		configure
		make_install
		exit $?;;
	bootstrap)
		configure
		make_install
		bootstrap_tests
		exit $?;;
	*)
		unit_tests
		rc_unittest=$?
		configure
		make_install
		regression_tests && exit $rc_unittest;;
esac
