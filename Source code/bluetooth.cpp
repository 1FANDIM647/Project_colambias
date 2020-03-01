/*
Program for  work with Bluetooth
Developed by Shishov Michael
  Email : fandim16k@gmail.com
  GNU 3.0
 */

#include <iostream>
#include <ctime>
#include <cstdlib>
#include <windows.h>

int pairDevice() {

	bool pairDevice(BLUETOOTH_DEVICE_INFO device){

DWORD errorCode;
bool result=false;
//wchar_t passKey=L'1234\n';
PWSTR * passKey = new PWSTR[1];
passKey[0]=L"1234";// this is the default pass key/pin code for HC-05, can be changed to a custom value.
errorCode=BluetoothAuthenticateDevice(NULL,m_radio,&device,*passKey,4); //here 4 is the size of device passkey

//errorCode=BluetoothRegisterForAuthenticationEx(&device, &hRegHandle, (PFN_AUTHENTICATION_CALLBACK_EX)&bluetoothAuthCallback, NULL);
//       if(errorCode != ERROR_SUCCESS)
//           {
//              fprintf(stderr, "BluetoothRegisterForAuthenticationEx ret %d\n", errorCode);
//              CloseAllHandle();
//               _getch();
//               return false;
//              //ExitProcess(2);
//
//           }//errorCode = BluetoothAuthenticateDeviceEx(NULL,m_radio, &device, NULL, MITMProtectionNotRequired);
switch(errorCode)
{case(ERROR_SUCCESS):
cout<<"Device authenticated successfully"<<endl;
result=true;
break;
case(ERROR_CANCELLED):
cout<<"Device authenticated failed"<<endl;
result=false;
break;
case(ERROR_INVALID_PARAMETER):
cout<<"Invalid parameters"<<endl;
result=false;
break;
case(ERROR_NO_MORE_ITEMS):
cout<<"Device not available"<<endl;
result=false;
break;
}

if(errorCode != ERROR_SUCCESS)
cout<<"Failure due to: "<<GetLastError() <<endl;

return result;
}

void CloseAllHandle(void){

if(CloseHandle(m_radio) == FALSE){
cout<<"CloseHandle() failed with error code "<< GetLastError()<<endl;
}
BluetoothUnregisterAuthentication(hRegHandle);

}
}

int main( )
{
	// create virtual port 

	if(desired_device_info.fAuthenticated==FALSE){ //if device is not authenticated then,
BluetoothGetDeviceInfo(m_radio,&desired_device_info); //get updated device information
if(!pairDevice(desired_device_info)){//attempt to pair with the device.
cout<<"Authentication failed, Try manually"<<endl;
CloseAllHandle();
return 0;}
}

ret=BluetoothSetServiceState(m_radio,&desired_device_info,&serial,BLUETOOTH_SERVICE_ENABLE);
if(ret !=ERROR_SUCCESS && ret!=E_INVALIDARG){
if(ret == ERROR_INVALID_PARAMETER)
cout<< "Invalid Parameter" << endl;
if(ret == ERROR_SERVICE_DOES_NOT_EXIST)
cout<< "Service not found" << endl;

cout<<"Press any key to exit"<<endl;
CloseAllHandle();
x=_getch();
return 0;
}

BluetoothGetDeviceInfo(m_radio,&desired_device_info); //get updated device infor

BluetoothUpdateDeviceRecord(&desired_device_info);

	return 0;
}