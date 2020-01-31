/*

main window of program

developed by : Shishov Michael

email:fandim16k@gmail.com

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


class mainWindow {

public: // Open members of class

// width and heigt of mainWindow
float width_mainWindow =1400  ;
float height_mainWindow =960 ;
// we can change size  of window
bool size = true;



void panel () {

 float height =960 ;
 float width =1400 ;



 // plus_button is main  button  on our  panel .
 void button1 ( ) {

  char name = " Menu" ;

   void button2()
   // button of PC characteristics
   char name = "show my PC characteristics ";
   void show_PC_characteristics ();
   int getting_info_device ();

  }

  void button3() {
  //button to show information of Disks
  char name = "show Disk information ";
  void show_Disk_information ();

  }
  void button4() {
  // we delate unneeded files in the folder ,  which  user pointed .
  char name = "clear unneeded files ";
  void open_folder();
  /*
   Now we can delete unneeded files

   1. first function collect those files
   2. second function delete those files
  */

  void gcCollect(){
    //execvp("rm", "cppgc.cpp");//Без этой строки алгоритм просто нельзя назвать корректным.
    gcChunk* newFirstChunk = currentChunk = new gcChunk;
    currentChunk->next = nullptr;
    currentOffset = 0;
    chunkCount = 1;

    for (auto i = referencesStack.begin();i != referencesStack.end(); ++i )
          gcMove(*i);

          //Collecting is over ,  now we can send  these files in needed place .
           gcChunk iter = firstChunk;
           firstChunk = newFirstChunk;
          while (iter != nullptr){
              gcChunk* t = iter->next;
              delete[] iter;
              iter = t;
          }
      }

      bool isPointer(gcHeader a){
       return (a.gcData[REF_COUNT] & 1) == 0;
   }

  }

  void button5 () {
   // button of tools  for  work with virtual disks
     char name = Tools;
     void system_srceen (); // system_srceen for  service calls
     void window_tools ();


  }



}

 void gcMove(gcHeader** current){
       if (*current == nullptr)
           return;
       if (isPointer(**current)){//we send object to needed place
           (*current) = (*current)->post_gcAddress;
           return;
       }
       gcHeader* new_obj = gcRawAlloc((*current)->gcData[STRUCT_SZ], (*current)->gcData[REF_COUNT]);
       memcpy(new_obj, (*current), sizeof(char) * (*current)->gcData[STRUCT_SZ]);

       gcHeader** iterator = reinterpret_cast<gcHeader**>(new_obj) + 1;


       (*current)->post_gcAddress = new_obj;
       (*current) = new_obj;
       int refCount = new_obj->gcData[REF_COUNT] >> 1;
       for (int i = 0; i < refCount; ++i, ++iterator)
           gcMove(iterator);
   }

   bool isPointer(gcHeader a){
    return (a.gcData[REF_COUNT] & 1) == 0;
}



};

// Registration of user
class Registration {




};

/*we created this class for manage by memory  ,  we can put  something in memory or get out from that
 */


int main () {


window.ENTER ( ) {
// window for entrance

// width and height 0f  window
window.width =900;
window.height =1500;

void button_text () {

// text for password
   void text1( ) {
     cout<<"enter password"
     cin>>password;

     if (password !=user_password ){

       cout<<"Enter password again!!! "<<endl;

     }
     //end
   }


    void text2 ( )
    {
      // text for login
      cout<<"enter login"
      cin>>login;

      if (login != user_login) {
      cout<<"Enter login again!!! "<<endl;

      }
      // end
    }

}


}

system ("chcp 1251>nul");

return 0 ;


}
