
#include <stdio.h>
#include <math.h>



int first_number_for_sum;
int second_number_for_sum;
int just_a_number;
int loop_number;



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



int main ()
{
    int multiplyX( int just_a_number , int loop_number);
    int eval_sum(int first_number_for_sum , int second_number_for_sum);

    return 0;
}