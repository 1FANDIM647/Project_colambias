/* Oprional  functions in Virtual Box  */

#include <iostream.h>
#include <string>
#include <iostream>
#include <window.h>
#include <string.h>
#include "proccessorx86.h"
#include "GARBAGE COLLECTOR.h"

using namespace std ;


class Virtual_box
{
public:
 void Virtual_box_ (){
 /*I will describe all functions of  Virtual box  */
   void creating_of_name_of_VB ()
   { // creating name for Virtual box
      string Name_VB;

      cout<<"Enter name of your Virtual box "
      cin >> Name_VB;
   }

   void creating_size_of ()
   {
     // creating size of Virtual box
     int Size_of_VB ;

     cout<<"Enter size of virtual box"
     cin>>Size_of_VB;

   }

}
}

int int main(int argc, char const *argv[]) {

// WRITE MAIN window of  programm  and  function of object (from class )

int password ; // variable for password
// Main part of program
void begin_of_virtual_box ()
{
   cout<< "Enter password :"
   cin>>password;

  switch (password) {
    case 1111:
        Virtual_box BOX1 ;
        Box.Virtual_box_();
          
    break;

    default :
    // If your password
   cout<<"Your  password is wrong "<<endl;
  }
}

  return 0;
}
