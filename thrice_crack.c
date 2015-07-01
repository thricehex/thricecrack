/*
Simple DES encryption cracking program utilizing dictionary
and brute force attacks

Author: Garrett Smith(ThriceHex)
Version: 6.30.15
*/

#define _XOPEN_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#define MIN_CHAR 32
#define MAX_CHAR 126

void iter_char(int);
void hash_cmp(char *);
int dict_attck();
void parse_opt(int, char **);

FILE *wl;
char *s;
char word[128];
char user_wordlist[256];
char hash_pw[32];
char salt[4];
int size = 4;
long long count = 0;
int dict = 1, brute = 1, result = 0;

int main(int argc, char **argv)
{
	parse_opt(argc, argv);
	salt[0] = hash_pw[0];
	salt[1] = hash_pw[1];
	salt[2] = '\0';
	
	if(dict)
	{
	printf("[+] Beginning dictionary attack on hash %s\n\n", hash_pw);
	result = dict_attck();
	}

	if(brute && !result)
	{
	s = malloc(size * sizeof(char) + 1);
	s[size] = '\0';
	int pos = size - 1;
	double possibl_val = pow(95, size);
	printf("[+] Brute forcing hash '%s' using all possible %d char permutations\n",
		hash_pw, size);
	
	printf("There are %le possible values.\t Max ETA: %f hours\n\n", 			possibl_val, (possibl_val / 250000.0) / 60.0 /60.0);


	iter_char(pos);
	}
	return 0;
}

void iter_char(int pos)
{
	if(pos == -1)
		return;

	int i;
	for(i = MIN_CHAR; i <= MAX_CHAR; i++)
	{
		s[pos] = i;
		iter_char(pos-1);
		hash_cmp(s);
	}
}

void hash_cmp(char *str)
{
	const char *hash = crypt((const char*) str, salt);
	
	if(!strcmp(hash_pw, hash))
	{
		printf("[!!] Matched hash '%s' with password '%s'\n", hash, str);
		printf("Hashes compared: %ld\n", count);
		if(s) free(s);
		if(wl) fclose(wl);
		exit(0);
	}

	++count;
		
}

int dict_attck()
{
	int len = 0;
	wl = fopen(user_wordlist, "r");
	
	while(fgets(word, 128, wl))
	{
		word[strlen(word)-2] = '\0';
		hash_cmp(word);
	}
	
	printf("[-] Dictionary attack failed!\n");
	return 0;
	
}

void parse_opt(int count, char **args)
{
	int i, need_c = 0, need_p = 0, need_w = 0;
	char next[256];

	char *USAGE = "USAGE:\n\t -p <hash_string> denotes the taget hash.(**Must be first argument**)\n\t -w wordlist to be used for dictionary attack(**Must use \\r\\n line terminations**) \n\t-d Only the dictionary attack should be used.\n\t -b Only the exhaustive brute-force attack should be used.\n\t-c # Denotes the length to use for the brute force attack(defaults to 4).\n\t-h displays this help message and exits.";

	for(i = 1; i < count; ++i)
	{
		strcpy(next, args[i]);

		if(need_c)
		{	
			size = atoi(next);
			need_c = 0;
		}
		else if(need_p)
		{
			strncpy(hash_pw, next, 32);
			need_p = 0;
		}
		else if(need_w)
		{
			strncpy(user_wordlist, next, 256);
		}
		else if(!strcmp("-d", next))
		{
			brute = 0;
		}
		else if(!strcmp("-b", next))
		{
			dict = 0;
		}
		else if(!strcmp("-c", next))
		{
			need_c = 1;
		}
		else if(!strcmp("-p", next))
		{
			need_p = 1;
		}
		else if(!strcmp("-w", next))
		{
			need_w = 1;
		}
		else if(!strcmp("-h", next))
		{
			printf(USAGE);
			exit(0);
		}

	}
	
	if(user_wordlist == NULL && dict == 1)
	{
		printf(USAGE);
		exit(0);
	}
}




