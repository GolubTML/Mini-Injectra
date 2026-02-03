compile_injectra:
	gcc src/miniInjectra.c -o obj/miniInjectra -ldl -pthread

compile_payload:
	gcc -shared -fPIC src/payload.c -o obj/payload.so

run: compile_injectra compile_payload
	./obj/miniInjectra $(PID) $(LIB_PATH)

clear:
	rm -f obj/miniInjectra obj/payload.so