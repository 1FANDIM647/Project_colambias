/*Open source of application
  "Blessed Home "
  Developed by Shishov Michael
  Email : fandim16k@gmail.com
 */
#include<iostream>
#include <cstdlib>
#include<SFML>
#include<string>
#include<microcontroler>// include library for work with microcontroler 
#include<ctime>
/*include  tools for controle smart room  */
/*include "v8 " for work with JavaScript   */
#include <include\v8.h>
#include <include\libplatform\libplatform.h>

/*we need connect program "generate_cards" 
for creating personal number ID of User .  */

#include "generate_cards.cpp"

/*connect main microcontroller*/
#include <maincontroller.h>

/*connect to bluetooth*/
#include "bluetooth.cpp"

using namespace std;




/*****USER*****/

class USER {
public:   
    // name of user 
     string name;
     int ID_code;

     /*this function  described  in  program "generate_cards.cpp" */
    int generate_of_numbers ();     
   // function to get phone number 

   int  get_for_number (){
    // variable will contains phone  our  user
    int phone_of_user;
      cout<<"Enter phone number :"
      cin>>phone_of_user;
      //input of  phone number

      cout<<"Phone"<<phone_of_user<<endl;
    return 0;

   } 
  // function  creating  of  name  
  
  int create_name(string name) 
  {
    cout<<"Name";
    cin>>name;
    return0;
  }



};



/*****door*****/
class main_door_in_flat
{
public:
    /*
    Variables for openning and closing of door
    */
    string.name_of_door;
    bool open_door;
    bool trigger_in_door;
    bool opening_door(bool trigger_in_door)
    {
        bool trigger_in_door = true;
        bool opener_locker = true;
        for (int i = 0; i < 1; ++i)
        {
            // locker is openning the door in room
            int open_locker();
            // from library  microcontroler 
        }
        return true;
    }
    bool closing_door(bool trigger_in_door)
    {
        bool trigger_in_door = false;
        bool opener_locker = false;
        if (opener_locker = false)
        {
            // closing the  door 
            for (int i = 1; i > 0; i--)
            {
                // locker is closing the door in room
                int close_locker();
                // int close_locker (); it is from library  microcontroler 
            }
        }

        return  false ;
    }
};
/*****light *****/
class light_in_rooms
{
public:
    string.name_of_room;

    bool trigger_in_room;
    bool light;
    bool turning_on_and_turning_off_light(bool trigger_in_room)
    {    /*we tap on screen we turning on or turning off
         light
         label tap "turning off/on" , which located  in function
         "tap_on_screen"
         */

        bool tap_on_screen;
        if (tap_on_screen = true)
        {
            bool trigger_in_room = true;
            do {
                void light_in_lamps_is_on();// assembler code in microcontroler 

            } while (trigger_in_room = true);

        }
        if (tap_on_screen = false)
        {
            bool trigger_in_room = false;
            do {
                void light_in_lamps_is_off();// assembler code in microcontroler 
            } while (trigger_in_room = false);

        }
        return  true;

    }
};

/*****water_in_home*****/
   
class water_device {
public :
    bool water_cold;
    bool water_hot;
    bool trigger_in_crane_of_hot_water;
    bool trigger_in_crane_of_cold_water;
    bool tap_on_button_H;// variable of our button for hot water
    bool tap_on_button_C;// variable of our button for cold water

  
    bool turn_on_hot_water_in_home( bool trigger_in_crane_of_hot_water ) {
        if (trigger_in_crane_of_hot_water = true)
        {            
            bool water_hot = true;
            bool water_cold = false;
            do {
                // Assembler code 
                int open_crane( );
                int start_hot_water();
            } while (water_hot = true;)
        }      
        else
        {  
            bool water_cold = false;
            bool water_hot = false;
            int close_crane ();
        }
        return  true;
  }

    bool turn_on_cold_water_in_home(bool trigger_in_crane_of_cold_water) {
        if (trigger_in_crane_of_cold_water = true)
        {
            bool water_hot = false;
            bool water_cold = true;
            do {
                // Assembler code 
                int open_crane();
                int start_hot_water();
            } while (water_cold = true;)
        }
        else
        {
            bool water_cold = false;
            bool water_hot = false;
            int close_crane();
        }
        return  true;
    }

    // function for labels  " on/off hot water " and "on/off cold water"

    bool slide_water(bool tap_on_button_H , bool tap_on_button_C) {
        if (tap_on_button_H = true) {
            bool turn_on_hot_water_in_home();
            return true;
         }
        else {
            return false;
        }
        if (tap_on_button_C = true) {
            bool turn_on_cold_water_in_home();
            return true;
        }
        else {
            return false;
        }
        if (tap_on_button_C&& tap_on_button_H = true)
        {
            int close_crane();
            return true; 
        }
        else {
            return false;
        }
        
      
     }

};

// opening and closing of curtains in room 

class curtains_in_room () {
public :
    /*
        Variables for openning and closing of door
        */
    string.name_of_curtains;
    bool open_curtains;
    bool trigger_in_curtains;
    bool opening_curtains(bool trigger_in_curtains)
    {
        bool trigger_in_curtains = true;
        bool opener_locker = true;
        for (int i = 0; i < 3; ++i)
        {
            // locker is openning the curtains in room
            int open_locker();
            // from library  microcontroler 
        }
        return true;
    }
    bool closing_curtains(bool trigger_in_door)
    {
        bool trigger_in_door = false;
        bool opener_locker = false;
        if (opener_locker = false)
        {
            // closing the  curtains 
            for (int i = 3; i > 0; i--)
            {
                // locker is closing the curtains in room
                int close_locker();
                // int close_locker (); it is from library  microcontroler 
            }
        }

        return false ; 
    }

   
};

class conditioner() {
public:
    int work_conditioner() {
        int temperature_in_C; // for measuring of temperature in C graduses 
        int temperature_of_conditioner;
        bool trigger_in_conditioner;
        bool press_on_screen_conditioner;
        // functions of increase and decrease in conditioner 
        int temperature_in_conditioner (bool trigger_in_conditioner, bool press_on_screen_conditioner, int temperature_of_conditioner)
        {

            if (press_on_screen_conditioner = true)
            {
                bool trigger_in_conditioner = true;
                do {
                    for (int i = 0; i < 1; i++) {
                        int value_of_temperature++;
                        float increase_of_temperature();// assembler code 
                        cout << "Температура в комнате " << value_of_temperature << endl;
                    };
                } while (trigger = true)
            }
            if (press_on_screen_conditioner = false)
            {
                bool trigger_in_conditioner = false
                    do {
                        for (int i = 0; i < 1; i++) {
                            int value_of_temperature--;
                            float increase_of_temperature();// assembler code 
                            cout << "Температура в комнате " << value_of_temperature << endl;
                        };
                    } while (trigger = false)
            }
            return  trigger_in_conditioner,  press_on_screen_condtioner,   temperature_of_conditioner;
        }
        return  value_of_conditioner;

    }

    /*Function  for measuring of the temperature    */
    int  measure_of_temperature(int temperature_in_C )
    {
        int temperature_in_F;
        temperature_in_F =9/5*temperature_in_C+32;
        
        cout<<"temperature in F :"<<temperature_in_F <<endl;
        
        return 0;

    }
};

    




int main ()
{  /* load all labels in this program thanks of "tools.cpp"
       
   */
   
   system();
    
    system("chcp1251>nul");
 
  /*OBJECTS*/

/*****user*****/

/*creating  of user . we add 
4 functions for  our  object .  */
 USER user1;
  user1.create_name();
  user1.generate_of_numbers (); 
  user1.get_for_number(); 

  /*****object_door *****/
  main_door_in_flat door_first;
  // door_first is getting two function
  door_first.name_of_door = "";
  door_first.opening_door();
  door_first. closing_door ();
  /*****light *****/
  //room1
  light_in_rooms room1;
  room1.name_of_room = "room1"
      room1. turning_on_and_turning_off_light();
  //room2
  light_in_rooms room2;
  room2.name_of_room = "room2";
      room2. turning_on_and_turning_off_light();
  //room3
  light_in_rooms room3;
  room3.name_of_room = "room3";
      room3. turning_on_and_turning_off_light();
  //room4
  light_in_rooms room4;
  room4.name_of_room = "room4";
      room4. turning_on_and_turning_off_light();

 /*****conditioner *****/ 
      conditioner Conditioner;
      Conditioner.work_conditioner();
 /*****water*****/
      water_device crane;
      crane.slide_water();
      crane.measure_of_temperature();
/*****curtains*****/
      main_door_in_flat door_first;
      // door_first is getting two function
      door_first.curtains_in_room = "Door";
      door_first. opening_curtians();
      door_first. closing_curtians();
  return 0;
  }