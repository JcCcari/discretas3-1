#include <iostream>
#include <vector>
#include <string>
#include <NTL/ZZ.h>
using namespace std;
using namespace NTL;

typedef long long int ll;

class rsa
{
	private:
		//string alfabeto;
		ZZ p;
		ZZ q;

		ZZ n;
		ZZ fn; //# fi de n
		ZZ d; // clave privada , inversa de e
		ZZ e; // clave publica 
	public:		
		string alfabeto ="abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

		long long   size = alfabeto.size();		
		rsa(int nbits);																									// solo falta agregar que genere claves correctamente osea numero de por ejemplo 1024 bits																			
		rsa(ZZ nn, ZZ ee);																								// 
		rsa(ZZ pp, ZZ qq,ZZ ee);																						
		
		void generarClaves(int nbits);																					//


		void cifrar(); // no van a retornar nada, por ahora dejarlo ahi xD												//
		ZZ cLetra(string posPlano); 																						//

		void descifrar();																								//
		ZZ dLetra(ZZ cifrado);																							//


		bool find(vector<ll>& lista,ll inicio,ll fin,ll& elemento); //BUSQUEDA BINARIA

		ZZ tRestoChino(ZZ posCifrado);																					//
		ZZ get_q_inicial(ZZ P, ZZ p_or_q);																				//
		//
		ZZ mod(ZZ a , ZZ b); 																							//
		ZZ exp(ZZ a, ZZ b, ZZ m); ///exp. modular rapida  																//
		//ll expBinaria(ll a, ll b ,ll m); //exp. binaria modular

		//TEST'S DE PRIMALIDAD
		vector<ll> cribaEratostenes(ll inicio, ll final); // halla los primos en un rango de [inicio,fin]
		//bool primo(ZZ  n);// comprueba si el numero es primos 															//
		bool millerRabin(ZZ n);
		bool fermat(ZZ n);

		ZZ expoBits(ZZ nbits);																							// 
		ZZ mcd(ZZ a,ZZ b); //euclides binario																			//
		ZZ eExtendido(ZZ a,ZZ b); 																						//

		string get_file_contents(const char* filename);																	//

			/*		CONVERSIONESS 		*/
		string ZZtos(ZZ num);																							//
		ZZ stoZZ(string str);																							//		
		bool ZZtoBool(ZZ number);																						//

		string convertirRellenarCeros(string cadenaString);
		string rellenarCeros(string cadena,long long cantidad);


};
