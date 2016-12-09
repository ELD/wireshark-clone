project4:
	/u/wy/iq/edattore/.cargo/bin/cargo build --release
	cp target/release/wireshark-clone .

clean:
	/u/wy/iq/edattore/.cargo/bin/cargo clean
	rm -rf wireshark-clone

