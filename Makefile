CC = x86_64-w64-mingw32-g++
CFLAGS = -O3 -Wall -Wextra
TARGET = tldr.exe
OBJS = main.o peutils.o utils.o

all: $(TARGET)

$(TARGET): $(OBJS)
		$(CC) $(OBJS) -o $(TARGET)

main.o: src/main.cpp
		$(CC) -c src/main.cpp $(CFLAGS)

peutils.o: src/peutils.c 
		$(CC) -c src/peutils.c $(CFLAGS)

utils.o: src/utils.c 
		$(CC) -c src/utils.c $(CFLAGS)


clean: 
		rm $(TARGET) $(OBJS)
