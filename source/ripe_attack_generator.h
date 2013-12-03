/* RIPE was originally developed by John Wilander (@johnwilander)
 * and was debugged and extended by Nick Nikiforakis (@nicknikiforakis)
 *
 * Released under the MIT license (see file named LICENSE)
 *
 * This program is part the paper titled
 * RIPE: Runtime Intrusion Prevention Evaluator 
 * Authored by: John Wilander, Nick Nikiforakis, Yves Younan,
 *              Mariam Kamkar and Wouter Joosen
 * Published in the proceedings of ACSAC 2011, Orlando, Florida
 *
 * Please cite accordingly.
 */

/**
 * @author John Wilander
 * 2007-01-16
 */

#ifndef RIPE_ATTACK_GENERATOR_H
#define RIPE_ATTACK_GENERATOR_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <getopt.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "ripe_attack_parameters.h"

typedef int boolean;
enum booleans {FALSE=0, TRUE};

#define DEFAULT_DUMP_SIZE 192
#define HEX_STRING_SIZE 11  /* Including null terminator */

#define DEBUG_MEMDUMP "./result/debug_memdump.txt"

typedef struct attack_form ATTACK_FORM;
struct attack_form {
  enum techniques technique;
  enum inject_params inject_param;
  enum code_ptrs code_ptr;
  enum locations location;
  enum functions function;
};

typedef struct char_payload CHARPAYLOAD;
struct char_payload {
  enum inject_params inject_param;
  size_t size;
  void *overflow_ptr;  /* Points to code pointer (direct attack) */
                       /* or general pointer (indirect attack)   */
  char *buffer;

  jmp_buf *jmp_buffer;

  long stack_jmp_buffer_param;
  size_t offset_to_copied_base_ptr;
  size_t offset_to_fake_return_addr;
  long *fake_return_addr;
  long *ptr_to_correct_return_addr;
};

typedef struct memory_dump MEM_DUMP;
struct memory_dump {
  char address[HEX_STRING_SIZE];
  char value[HEX_STRING_SIZE];
};

struct attackme{
    char buffer[256];
    int (*func_ptr)(const char *, int);
};

/**
 * main
 * -t technique
 * -i injection parameter (code + NOP / return-into-libc / param to system())
 * -c code pointer
 * -l memory location
 * -f function to overflow with
 * -d output debug info (set to 't' for TRUE)
 * (-e output error messages)
 * -o set output stream
 */
int main(int argc, char **argv);

void perform_attack(FILE *output_stream,
		    int (*stack_func_ptr_param)(const char *),
		    jmp_buf stack_jmp_buffer_param);

/* BUILD_PAYLOAD()                                                  */
/*                                                                  */
/* Simplified example of payload (exact figures are just made up):  */
/*                                                                  */
/*   size      = 31 (the total payload size)                        */
/*   size_sc   = 12 (size of shellcode incl NOP)                    */
/*   size_addr = 4  (size of address to code)                       */
/*   size_null = 1  (size of null termination)                      */
/*                                                                  */
/*    ------------ ----------------- ------------- -                */
/*   | Shell code | Padded bytes    | Address     |N|               */
/*   | including  |                 | back to     |u|               */
/*   | optional   |                 | NOP sled or |l|               */
/*   | NOP sled   |                 | shell code  |l|               */
/*    ------------ ----------------- ------------- -                */
/*    |          | |               | |           | |                */
/*    0         11 12             25 26         29 30               */
/*              /   \             /   \             \               */
/*     size_sc-1     size_sc     /     \             size-size_null */
/*                              /       \                           */
/*  (size-1)-size_addr-size_null         size-size_addr-size_null   */
/*                                                                  */
/* This means that we should pad with                               */
/* size - size_sc - size_addr - size_null = 31-12-4-1 = 14 bytes    */
/* and start the padding at index size_sc                           */
boolean build_payload(CHARPAYLOAD *payload);

boolean contains_terminating_char(unsigned long value);
void remove_terminating_chars(char *contents, size_t length);
void remove_nulls(char *contents, size_t length);

void set_technique(char *choice);
void set_inject_param(char *choice);
void set_code_ptr(char *choice);
void set_location(char *choice);
void set_function(char *choice);

int dummy_function(const char *str) {
  return 0;
}

void save_memory(struct memory_dump *dump, char *start, size_t size);
void print_payload_info(FILE *stream, CHARPAYLOAD *payload);
void print_memory(FILE *stream, char *start, size_t words);
void print_two_memory_dumps(FILE *stream,
		       struct memory_dump *dump1,
		       struct memory_dump *dump2,
		       size_t size);
void print_three_memory_dumps(FILE *stream,
		       struct memory_dump *dump1,
		       struct memory_dump *dump2,
		       struct memory_dump *dump3,
		       size_t size);

boolean is_attack_possible();
void homebrew_memcpy(void *dst, const void *src, size_t len);

//NN
void gadget1(int a, int b);
void gadget2(int a, int b);
int  gadget3(int a, int b);

#endif /* !RIPE_ATTACK_GENERATOR_H */
