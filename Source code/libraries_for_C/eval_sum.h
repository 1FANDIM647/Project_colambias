
#include <stdio.h>
#include <math.h>


// variables for functions  below
int first_number_for_sum;
int second_number_for_sum;
int just_a_number;
int loop_number;
int var_address;


// Function for counting of two numbers
void eval_sum (int first_number_for_sum , int second_number_for_sum )
{
     int result = first_number_for_sum + second_number_for_sum;
     printf("%d",  result );

}
//Function for  multiplication number is multipling itself definition time
void    multiply_in_X( int just_a_number , int loop_number)
{
    // number is multipling itself differently times

    while (just_a_number <= loop_number)
    {
      int  result_of_multiplyX = just_a_number*just_a_number;
    }

}
// output of variable
void  address_of_variable ( int  var_address)
{

  printf(" %d , %p Address of this variable:" , var_address&var_address);
}

int main ()
{
  //load all functions
    void multiplyX( int just_a_number , int loop_number);
    void eval_sum(int first_number_for_sum , int second_number_for_sum);
    void address_of_variable(int  var_address);
    return 0;
}
