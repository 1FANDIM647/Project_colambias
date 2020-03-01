/* Program for control of microcontrolers  */

#include <"stdlib.h">
#include <"math.h">
#include <"string">
#include <"assert.h">
//include controllers
#include <light_controller.h>

/* microcontroler for work in conditioner */
struct  microcontroler_conditioner {

  string name;
  int registers;

  // unservice registers
  string  name_of_registers [] = {"AA1","AA2","AA3","AA4","AA5","AA6","AA7","AA8","AA9","AA10","BB1","BB2","BB3","BB4","BB5","BB6","BB7","BB8","BB9","BB10" ,

                                "CC1","CC2","CC3","CC4","CC5","CC6","CC7","CC8","CC9","CC10" ,"DD1","DD2","DD3","DD4","DD5","DD6","DD7","DD8","DD9","DD10"  } ;
   


};



int  main(int argc, char const *argv[]) {

  return 0;
}
