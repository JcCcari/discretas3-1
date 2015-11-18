#include "rsa.h"
#include <iostream>
#include <fstream>
#include <NTL/ZZ.h>
using namespace std;
using namespace NTL;

ZZ stoZZ(string num)
{
	ZZ conv(INIT_VAL , num.c_str());
	return conv;
}
string get_file_contents(const char *filename)
{
 	ifstream in(filename, std::ios::in | std::ios::binary);
  if (in)
  {
    return(string( (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>() ));
  }
}

int main()
{
	int choose;
	cout << "\t***************  CIFRADO RSA  *****************"<<endl;
	cout <<" [1] Encriptar \n [2] Desencriptar \n [3] Generar Claves \n" <<endl;
	cout << "Elija una opcion :";
	cin >> choose;
	
	if(choose == 1)
	{
		ZZ n,e;
		n = stoZZ (get_file_contents("clave_n.txt") );
		e = stoZZ (get_file_contents("clave_e.txt") );
		//cout << n <<"\n"<<e << endl;
		//cout << "Ingrese el [n] [e]: ";
		//cin>> n >> e ;
		//cin.get();

		rsa rsa(n,e);
		rsa.cifrar();
	}
	else if( choose == 2)
	{
		ZZ p,q,e;
		cout << "Ingrese [p] [q] [e]: ";
		cin>> p >>q >> e;
		cin.get();
		rsa rsa(p,q,e);
		rsa.descifrar();
		
	}
	else if (choose ==3)
	{
		int numBits; 
		cout << "Ingrese el numero de bits: " ;
		cin >> numBits;
		rsa rsa(numBits);
	}
	else
		cout << " Vuelva a ingresar otra opcion "<< endl;

	return 0;
}
