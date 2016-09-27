hsainfo: hsainfo.c
	$(CC) -I/opt/rocm/hsa/include -L/opt/rocm/hsa/lib -o hsainfo hsainfo.c -lhsa-runtime64
