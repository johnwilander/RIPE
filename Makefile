# Makefile for RIPE
# @author John Wilander & Nick Nikiforakis

#Depending on how you test your system you may want to comment, or uncomment
#the following
CFLAGS=-fno-stack-protector
CC=gcc
all: ripe_attack_generator

clean:
	rm ./build/*


# ATTACK GENERATOR COMPILE
ripe_attack_generator: ./source/ripe_attack_generator.c
	${CC} ${CFLAGS} ./source/ripe_attack_generator.c -o ./build/ripe_attack_generator 
	

