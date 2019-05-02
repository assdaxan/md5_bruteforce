#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "md5.h"

//#define DEBUG
#define MULTI_THREAD

int32_t flag = 0;

typedef struct ThreadArgv{
	int32_t len;
	int32_t start_char;
	int32_t end_char;
	uint8_t *hash;
}Argv;

void md5(uint8 *passwd_string, uint32 passwd_string_len, uint8 *hash) {
	md5_context ctx;

	md5_starts(&ctx);
	md5_update(&ctx, passwd_string, passwd_string_len);
	md5_finish(&ctx, hash);
}

void *bruteforce(void *ptr){
	Argv *data = (Argv *)ptr;
	uint8_t hash2[16] = {0, };
	int32_t last = data->len-1;
	int32_t i = 0;
	int32_t tmp = 0;
	uint8_t *char_set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	int32_t char_set_len = strlen(char_set)-1;
	uint8_t *passwd_string = NULL;
	int32_t *cipher_brute_force_count_list = NULL;
	int32_t start_char_index = 0;
	int32_t end_char_index = char_set_len;
	int8_t *s = NULL;
	int8_t *e = NULL;
	
	// Calc Index
	s = strchr(char_set, data->start_char);
	e = strchr(char_set, data->end_char);
	start_char_index = ((int32_t)s - (int32_t)char_set)/sizeof(int8_t);
	end_char_index = ((int32_t)e - (int32_t)char_set)/sizeof(int8_t);
	
	cipher_brute_force_count_list = (int32_t *)malloc(sizeof(int32_t)*data->len);
	memset(cipher_brute_force_count_list, 0, sizeof(int32_t)*data->len);
	cipher_brute_force_count_list[0] = start_char_index;

	// Init passwd_string
	passwd_string = (uint8_t *)malloc(sizeof(uint8_t)*(data->len+1));
	memset(passwd_string, '\0', data->len+1);
	for(i=0; i<data->len; i++){
		tmp = cipher_brute_force_count_list[i];
		passwd_string[i] = char_set[tmp];
	}
	
	// Brute Force passwd_stirng
	// Ex : len = 5
	// [0, 0, 0, 0, 0]  = "aaaaa"
	// [0, 0, 0, 0, 1]  = "aaaab"
	//       ...
	// [0, 0, 0, 0, 61] = "aaaa9"
	// [0, 0, 0, 1, 0]  = "aaaba"
	while(1){
		#ifdef DEBUG
			printf("%s \n", passwd_string);
		#endif
		md5(passwd_string, data->len, hash2);
    	if(strncmp(data->hash, hash2, 16) == 0){
    		flag = 1;
    		printf("[!!] FOUND : %s \n", passwd_string);
    		break;
		}/**/
		if(++cipher_brute_force_count_list[last] > char_set_len){
			for(i=last; i!=0; i--){
				if(cipher_brute_force_count_list[i] > char_set_len){
					tmp = ++cipher_brute_force_count_list[i-1];
					passwd_string[i-1] = char_set[tmp];
					cipher_brute_force_count_list[i] = 0;
					passwd_string[i] = char_set[0];
				}
			}
			if(cipher_brute_force_count_list[i] > end_char_index){
				break; // [DONE]
			}
		}
		tmp = cipher_brute_force_count_list[last];
		passwd_string[last] = char_set[tmp];
	}
	
	printf("[DONE] LEN : %d RANGE(%c, %c)\n", data->len, data->start_char, data->end_char);
	free(cipher_brute_force_count_list);
	free(passwd_string);
}

int main(int argc, char **argv) { 
	// #################
	// # TEST DATA SET #
	// #################
	//uint8_t hash[16] = {0x45, 0xC4, 0x8C, 0xCE, 0x2E, 0x2D, 0x7F, 0xBD, 0xEA, 0x1A, 0xFC, 0x51, 0xC7, 0xC6, 0xAD, 0x26}; // 9
	//uint8_t hash[16] = {0xAC, 0x62, 0x7A, 0xB1, 0xCC, 0xBD, 0xB6, 0x2E, 0xC9, 0x6E, 0x70, 0x2F, 0x07, 0xF6, 0x42, 0x5B}; // 99
	//uint8_t hash[16] = {0xB7, 0x06, 0x83, 0x5D, 0xE7, 0x9A, 0x2B, 0x4E, 0x80, 0x50, 0x6F, 0x58, 0x2A, 0xF3, 0x67, 0x6A}; // 999
	//uint8_t hash[16] = {0xFA, 0x24, 0x6D, 0x02, 0x62, 0xC3, 0x92, 0x56, 0x17, 0xB0, 0xC7, 0x2B, 0xB2, 0x0E, 0xEB, 0x1D}; // 9999
	//uint8_t hash[16] = {0xD3, 0xEB, 0x9A, 0x92, 0x33, 0xE5, 0x29, 0x48, 0x74, 0x0D, 0x7E, 0xB8, 0xC3, 0x06, 0x2D, 0x14}; // 99999
	//uint8_t hash[16] = {0x84, 0x9F, 0x89, 0x11, 0xF2, 0xB6, 0x1D, 0x31, 0xA0, 0x4B, 0xA9, 0xAC, 0xE3, 0x0A, 0x5D, 0x4B}; // 9Zw
	//uint8_t hash[16] = {0x63, 0xA9, 0xF0, 0xEA, 0x7B, 0xB9, 0x80, 0x50, 0x79, 0x6B, 0x64, 0x9E, 0x85, 0x48, 0x18, 0x45}; // root
	//uint8_t hash[16] = {0xFA, 0x03, 0xEB, 0x68, 0x8A, 0xD8, 0xAA, 0x1D, 0xB5, 0x93, 0xD3, 0x3D, 0xAB, 0xD8, 0x9B, 0xAD}; // Root
	//uint8_t hash[16] = {0x05, 0x02, 0x48, 0xCD, 0x2E, 0xFA, 0xD7, 0x70, 0xE1, 0x94, 0xCA, 0x0E, 0x12, 0xD4, 0x42, 0x64}; // 1234a
	//uint8_t hash[16] = {0x7B, 0xE9, 0x35, 0xA5, 0x7A, 0x0E, 0x57, 0x42, 0xC2, 0x27, 0x6A, 0x32, 0x7D, 0x87, 0xB1, 0x98}; // i3A9
	//uint8_t hash[16] = {0x77, 0x71, 0x19, 0x76, 0xE9, 0x42, 0xD8, 0x09, 0x1A, 0x96, 0x42, 0x93, 0x49, 0xEF, 0xD6, 0xE2}; // szzz
	//uint8_t hash[16] = {0x59, 0x4F, 0x80, 0x3B, 0x38, 0x0A, 0x41, 0x39, 0x6E, 0xD6, 0x3D, 0xCA, 0x39, 0x50, 0x35, 0x42}; // aaaaa
	//uint8_t hash[16] = {0xF6, 0xA6, 0x26, 0x31, 0x67, 0xC9, 0x2D, 0xE8, 0x64, 0x4A, 0xC9, 0x98, 0xB3, 0xC4, 0xE4, 0xD1}; // AAAAA
	//uint8_t hash[16] = {0x21, 0xE4, 0xC7, 0x82, 0x43, 0x2C, 0x5F, 0xBD, 0x82, 0xAB, 0x70, 0xC2, 0x5B, 0x17, 0xCB, 0x3E}; // 9Av2Z
	uint8_t hash[16] = {0x4D, 0xD6, 0x16, 0xD1, 0xE0, 0xAD, 0x30, 0xFF, 0xB1, 0xFF, 0xBE, 0x4A, 0x0A, 0x11, 0x35, 0x22}; // jesan
	//uint8_t hash[16] = {0xE0, 0x2C, 0x96, 0x38, 0x94, 0x0C, 0x28, 0x0C, 0x92, 0x85, 0x0D, 0x8B, 0xFF, 0xE2, 0xA5, 0x25}; // j2Si4
	
#ifdef MULTI_THREAD
	// ############
	// # CHAR SET #
	// ############
	// "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	
	// Argv : {LEN, start_char, end_char, hash}
	Argv threat_data_list[] = {
								{1, 'a', '9', hash},
								{2, 'a', '9', hash},
								{3, 'a', 'z', hash},
								{3, 'A', '9', hash},
								{4, 'a', '9', hash},
								{5, 'a', 'b', hash},
								{5, 'c', 'd', hash},
								{5, 'e', 'f', hash},
								{5, 'g', 'h', hash},
								{5, 'i', 'j', hash},
								{5, 'k', 'l', hash},
								{5, 'm', 'n', hash},
								{5, 'o', 'p', hash},
								{5, 'q', 'r', hash},
								{5, 's', 't', hash},
								{5, 'u', 'v', hash},
								{5, 'w', 'x', hash},
								{5, 'y', 'z', hash},
								{5, 'A', 'B', hash},
								{5, 'C', 'D', hash},
								{5, 'E', 'F', hash},
								{5, 'G', 'H', hash},
								{5, 'I', 'J', hash},
								{5, 'K', 'L', hash},
								{5, 'M', 'N', hash},
								{5, 'O', 'P', hash},
								{5, 'Q', 'R', hash},
								{5, 'S', 'T', hash},
								{5, 'U', 'V', hash},
								{5, 'W', 'X', hash},
								{5, 'Y', 'Z', hash},
								{5, '0', '1', hash},
								{5, '2', '3', hash},
								{5, '4', '5', hash},
								{5, '6', '7', hash},
								{5, '8', '9', hash}
							};
	int32_t thread_count = sizeof(threat_data_list)/sizeof(Argv);
	int32_t thread_id=0;
	int32_t i=0;
	pthread_t thread_id_list[thread_count];

	// Run Thread
	for(i=0; i<thread_count; i++){
		thread_id = pthread_create(&thread_id_list[i], NULL, bruteforce, (Argv *)&(threat_data_list[i]));
		if (thread_id < 0){
	        perror("thread create error : ");
	        exit(0);
	    }
	}
	
	// Wait Threads Done
	while(1){
		if(flag == 1){
			printf("!! [THREAD] DONE !!\n");
			for(i=0; i<thread_count; i++){
				pthread_cancel(thread_id_list[i]);
				//pthread_detach(thread_id_list[i]);
			}
			break;
		}
		sleep(1);
	}
#endif
#ifndef MULTI_THREAD
	Argv data_list[] = {
						{1, 'a', '9', hash},
						{2, 'a', '9', hash},
						{3, 'a', '9', hash},
						{4, 'a', '9', hash},
						{5, 'a', '9', hash}
					};
	int32_t count = sizeof(data_list)/sizeof(Argv);
	int32_t i=0;

	for(i=0; i<count; i++){
		bruteforce((Argv *)&(data_list[i]));
		if(flag == 1){
			printf("!! [NO THREAD] DONE !!\n");
			break;
		}
	}
#endif
    return 0;
}
