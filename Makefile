project4:
	cargo build --release
	cp target/release/wireshark-clone .

clean:
	cargo clean
	rm -rf wireshark-clone

