all:
	rm -f /usr/lib64/libvhd.so.0 /usr/lib64/libblockcrypto.so
	tar cvfz /root/rpmbuild/SOURCES/blktap-master.tar.gz blktap-master
	rpmbuild -ba blktap.spec
	ln -s /root/rpmbuild/BUILD/blktap-master/vhd/lib/.libs/libvhd.so.0 /usr/lib64/
	ln -s /root/rpmbuild/BUILD/blktap-master/drivers/.libs/libblockcrypto.so /usr/lib64/
