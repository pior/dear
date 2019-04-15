# DEAR - Data encryption at rest

Experiments with storing small secret payload (like API secret keys) in database.

With a focus on the read/decryption speed.

Decryption by payload size:
```
BenchmarkDecryption/secretbox-32bytes-4         	 5000000	       364 ns/op	      32 B/op	       1 allocs/op
BenchmarkDecryption/aesgcm-32bytes-4            	 3000000	       567 ns/op	     944 B/op	       7 allocs/op

BenchmarkDecryption/secretbox-512bytes-4        	 1000000	      1314 ns/op	     512 B/op	       1 allocs/op
BenchmarkDecryption/aesgcm-512bytes-4           	 2000000	       747 ns/op	    1424 B/op	       7 allocs/op

BenchmarkDecryption/secretbox-8192bytes-4       	  100000	     12203 ns/op	    8192 B/op	       1 allocs/op
BenchmarkDecryption/aesgcm-8192bytes-4          	  300000	      3703 ns/op	    9104 B/op	       7 allocs/op
```

Encryption by payload size:
```
BenchmarkEncryption/secretbox-32bytes-4         	 1000000	      1160 ns/op	     112 B/op	       2 allocs/op
BenchmarkEncryption/aesgcm-32bytes-4            	 1000000	      1023 ns/op	     976 B/op	       7 allocs/op

BenchmarkEncryption/secretbox-512bytes-4        	 1000000	      2157 ns/op	     608 B/op	       2 allocs/op
BenchmarkEncryption/aesgcm-512bytes-4           	 1000000	      1248 ns/op	    1488 B/op	       7 allocs/op

BenchmarkEncryption/secretbox-8192bytes-4       	  100000	     13402 ns/op	    9504 B/op	       2 allocs/op
BenchmarkEncryption/aesgcm-8192bytes-4          	  300000	      4183 ns/op	   10384 B/op	       7 allocs/op
```
