all:
	g++ -c -Wall ./src/*.cpp
	g++ *.o -o CITRIC -lpcap -lz -lpcre
	mv *.o ./obj
	g++ -c -Wall ./src/showFGG/*.cpp
	g++ *.o -o showFGG
	mv *.o ./obj

clean:
	rm -f ./obj/*.o
	rm -f CITRIC
	rm -f showFGG

debug:
	g++ -g -c -Wall ./src/*.cpp
	g++ -g *.o -o CITRIC -lpcap -lz -lpcre
	mv *.o ./obj
	g++ -g -c -Wall ./src/showFGG/*.cpp
	g++ *.o -o showFGG
	mv *.o ./obj

