/*
It's one of parts of ANALITICS SOFTWARE
.this program analise you  videocard and makes
messsage about  characteristics your PC

DEVELPOPED BY Shishov Michael
email : fandim16k@gmail.com

*/
#include <analitics.>
#include <stdlib.h>
#include <math.h>
#include "ANALITICS_OS.cpd"
#include "GARBAGE COLLECTOR.h"
#include <iostream>
#include <window.h>
#include <string.h>
#include "proccessorx86.h"


using namespace std ;




int getting_info_device () {
// we get information about PC

get.videocard();
get.ram();
get.proccessor();

if (bool videocard = false ) {
//if user doesn't have videocard ,  we ask him  , to insert videocard in PC
cout << "You haven't videocard  "  <<endl;
cout << "Please insert videocard "  <<endl;

}

if (bool proccessor = false) {

  //if user doesn't have videocard ,  we ask him  , to insert proccessor in PC
  cout << "You haven't proccessor  "  <<endl;
  cout << "Please insert proccessor "  <<endl;
}

if (bool ram =false) {

  //if user doesn't have ram ,  we ask him  , to insert ram in PC
  cout << "You haven't ram  "  <<endl;
  cout << "Please insert ram "  <<endl;

}


return 0;

}


int  overloading_up_of_memory (int memory_size;) {

    double memory_size;
  /* we get size of  memory in terms of number. If  we have got big amount of memory we messsage about it .
     we get variable int memory_size
  */
  if ( memory_size>=1000 )
  {
     void window_message ( ) {
       // We print message  about this problem
       cout<<" Your memory is  overloaded ,  clean your disk !!! "<<endl;

     }
  }

  return memory_size;
}

void time   () {

   void window_function ( ) ;

   void window_message ( ) {

      // input of time
      cout <<"Year: "<<int year <<"| month:" <<int month<<"|minutes : "<<int minutes<<"|seconds:"<<int seconds<<endl;

   }

}


 int main() {

//we load all function
int create_main_window();
int overloading_up_of_memory();
int getting_info_device();



// we get all information and give result to our user
//


  return 0;
}
