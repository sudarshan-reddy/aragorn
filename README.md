# Aragorn

[![Rust](https://github.com/sudarshan-reddy/aragorn/actions/workflows/rust.yml/badge.svg)](https://github.com/sudarshan-reddy/aragorn/actions/workflows/rust.yml)

Proof of Concept of a a watcher tool that runs on user-space 
and monitors tcpdump for predefine-able patterns and has a 
configurable module to act upon these observed metrics.

As a Demonstration, the tool looks for Redis latencies and prints them to the console.

## Building 

Clone this repository and run Cargo build. You'll naturally need Rust installed.

## Running

Run the binary with the following command:

```bash
sudo ./target/debug/aragorn  --interface en0 --redis-port 6379
```

This will start the watcher on interface en0 and will look for Redis latencies on port 6379.

This then measures redis latencies by Key like so:

```bash
redis-cli
> set abc 123
OK
> RPUSH large_list $(seq 1 100000)
(integer) 24
```

This will print the latencies of the above commands to the console like so
```bash
     Running `target/debug/aragorn --interface en0 --redis-port 6379`
Key: setabc123, Latency: 35ms
Key: RPUSHlarge_list$(seq1100000), Latency: 39ms
````
