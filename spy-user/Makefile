lib:
	@ echo "Compilers used: $(CC), $(CXX)"
	$(CC) -fPIC -shared -g ./sgx_attacker.c -o libsgx_pte_attack.so

clean:
	rm libsgx_pte_attack.so