all: netfilter-test

netfilter-test: netfilter-test.o
	g++ -o netfilter-test netfilter-test.o -lnetfilter_queue
netfilter-test.o: netfilter-test.cpp
	g++ -c -o netfilter-test.o netfilter-test.cpp
clean:
	rm -f netfilter-test *.o
