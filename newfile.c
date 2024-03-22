#include <stdio.h>
#include <string.h>
#define _XOPEN_SOURCE
#include <unistd.h>
#include <crypt.h>

void chop(char *); /* chops a \n off the end of a word, replaces with \0 */

int main(int argc, char *argv[]){
  int i=0;
  char word[BUFSIZ],  salt[BUFSIZ], pwhash[BUFSIZ];
  FILE *words;
  words=fopen("/usr/share/dict/words","r"); /* open spelling dictionary */
  if(argc != 3){
    fprintf(stderr,"crack: usage\ncrack salt hashedpassword\n");
    return 2;
  }
  strcpy(salt,argv[1]);
  strcpy(pwhash,argv[2]);
  while( fgets(word,BUFSIZ,words) != NULL ){
    chop(word);
    if(strcmp((char*)crypt(word,salt),pwhash) == 0){ /* guessed the password ? */
      printf("the password is: %s\n",word);
      return 0;
    }
    if(strcmp(word,"nothing") == 0 || i%100 == 0)
      printf("word: %s\nsalt: %s\npwhash: %s\nhashguess: %s\n",
              word, salt, pwhash, (char*)crypt(word,salt));
    i++;
  }
  printf("The password is not in the spelling dictionary.\n");
  return 1;
}

void chop(char *word){
  int lenword;
  lenword=strlen(word);
  if( word[lenword-1] == '\n')
    word[lenword-1] = '\0';
}
