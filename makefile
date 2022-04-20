all: microblog.c
	gcc -Wall microblog.c -o microblog

run:
	@echo "Running microblog at: http://localhost:8080"
	./microblog

clean:
	rm microblog