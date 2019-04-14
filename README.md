# DEAR - Data encryption at rest

Experiments with storing small secret payload (like API secret keys) in database.
With a focus on the read/decryption speed.

Decryption time by payload size:
```
BenchmarkDecryption/secretbox-32bytes-4         	 3000000	       419 ns/op	      32 B/op	       1 allocs/op
BenchmarkDecryption/aesgcm-32bytes-4            	 3000000	       571 ns/op	     944 B/op	       7 allocs/op
BenchmarkDecryption/secretbox-512bytes-4        	 1000000	      1313 ns/op	     512 B/op	       1 allocs/op
BenchmarkDecryption/aesgcm-512bytes-4           	 2000000	       760 ns/op	    1424 B/op	       7 allocs/op
BenchmarkDecryption/secretbox-8192bytes-4       	  100000	     12518 ns/op	    8192 B/op	       1 allocs/op
BenchmarkDecryption/aesgcm-8192bytes-4          	  500000	      3847 ns/op	    9104 B/op	       7 allocs/op
```
