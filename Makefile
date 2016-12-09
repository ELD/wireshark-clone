project4:
	RUSTUP_HOME=/u/wy/iq/edattore/.multirust CARGO_HOME=/u/wy/iq/edattore/.cargo /u/wy/iq/edattore/.cargo/bin/cargo build --release
clean:
	RUSTUP_HOME=/u/wy/iq/edattore/.multirust CARGO_HOME=/u/wy/iq/edattore/.cargo /u/wy/iq/edattore/.cargo/bin/cargo clean
	rm -rf wireshark-clone

