#include "rsa.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <math.h>
#include <iomanip>
#include <iostream>
#include <stdlib.h>
#include <NTL/ZZ.h>
#include <string>
using namespace std;
using namespace NTL;

typedef long long int ll;


rsa::rsa(int nbits)
{
	//alfabeto ="abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	cout << "alfabeto: " << alfabeto << endl;
	//nbits=expoBits(nbits);
	cout << "# de" <<nbits<<" bits" <<endl;
	generarClaves(nbits);

	//primo(nbits);
}

rsa::rsa(ZZ nn , ZZ ee)
{
	//alfabeto ="abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	cout << "alfabeto: " << alfabeto << endl;
	 
	long long   size = alfabeto.size();
	n = nn;
	e = ee;

}

rsa::rsa(ZZ pp, ZZ qq,ZZ ee)
{
	//alfabeto ="abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	cout << "alfabeto: " << alfabeto << endl;
	 
	p = pp;
	q = qq;
	n = p*q;
	fn = (p-1)*(q-1);
	e = ee;
	d= mod(eExtendido(e,fn),fn);
}

void rsa::generarClaves(int nbits)
{
	ofstream Directorio ;
	ofstream clavesPrivadas;
	Directorio.open("Directorio publico.txt",ifstream::binary);
	clavesPrivadas.open("claves Privadas.txt",ifstream::binary);

	srand(time(0));
	while(true){ // generar # p
		p = GenPrime_ZZ(nbits);
		//p = mod(rand(),expoBits(nbits)-1 - expoBits(nbits-1)) +expoBits(nbits-1) ; // cambiar con random propio 
		//p = ZZ(17);
		//if( primo(p) )
		if (MillerWitness(p,ZZ(200)) == 0 )
			break;
	}

	cout <<"-----------------------"<< endl;
	while( true ){ //generar # q
		q = GenPrime_ZZ(nbits);
		//q = mod(rand(),expoBits(nbits)-1 - expoBits(nbits-1)) +expoBits(nbits-1) ;
		//q = ZZ(31);
		//if( primo(q) && q != p)
		if (MillerWitness(p,ZZ(200)) == 0 )
			break;
	}
	n = p*q; //generamos clave n
	fn=(q-1)*(p-1); //generamos # fn
	while(true){
		e = mod(RandomBits_ZZ(nbits),fn);
		//e=mod(rand(),fn);
		//e = ZZ(7);
		if( mcd(e,fn)==ZZ(1))
			break;
	}

	d=mod( eExtendido(e,fn) ,fn);
	cout <<" claves generadas xD \"Directorio publico.txt\" y \"claves Privadas.txt \" \n --------------------------------------------\n\n";

	Directorio << "Nombre: Jhoel \nClave n: "<< n << "\nClave e: "<< e << endl;

	clavesPrivadas << "p: "<< p <<"\n"<< "q: "<< q <<"\n"<< "n: "<< n <<"\n"<< "fn: "<< fn <<"\n"<< "e: "<< e <<"\n"<< "d: "<< d << endl ;

	clavesPrivadas.close();
	Directorio.close();
}

void rsa::cifrar()
{
	long long tamBloque = ZZtos(n).size()-1; // hallamos el tamaño de cada bloque para cifrar
	cout << " tamBloques: " << tamBloque << endl;

	
	ll dZZ = to_string(alfabeto.size()-1).size(); // hallamos el tamaño de la letra mas significativa(ultimo elemento) del alfabeto
	cout << "dZZ: "<< dZZ << endl;

	string tPlanoZZstring; //auxiliar, para concatenar c/u de las posiciones de las letras del tPlano
	ll tPlanoZZ; // posiciones de cada letra de tPlano

	//EMPEZAREMOS LEYENDO EL FICHERO QUE CONTIENE EL MENSAJE A CIFRAR
	string tPlano;// = get_file_contents("Mensaje Plano.txt");
	ifstream Plano;
	Plano.open("Mensaje Plano.txt",ifstream::binary);
	getline(Plano,tPlano);

	long long aux; // aux que almacenara la posicion en el alfabeto de la letra a cifrar.
	string auxS; // aux que sirve para aumentar los 0's que hagan falta para completar al tamanio de 
	cout << " auxS: "; 

	//empezamos convertir c/u de las letra de tPlano a una cadena de numeros
	int i=0;
	for(; i<tPlano.size() ;i++) // menos 1, porque en get_file_contents() se utiliza en rdbuf() que lee el archivo y al ultimo ingresa el -1, para no leer ese valor, restamos en 1 al la lectura del string que devuelve get_file_contents()
	{
		aux = alfabeto.find(tPlano[i]);
		auxS = to_string(aux);
		if ( auxS.size() < dZZ ) //si el tamaño de tPlano[i] < dZZ, entonces llenar con 0's a la izquierda
		{	
			int j=0;
			for (; j< dZZ - auxS.size() ;j++)
				auxS = "0"+auxS;
		}
		cout << auxS << " " ;
		tPlanoZZstring += auxS ;
	}

	cout <<"\ntPlanoZZstring: " << tPlanoZZstring <<"\n-----------------------------------------------------------------------------------"<<endl;

	int contaux=0; // aux que uso para contar cuantas veces aumento el digito mas significativo
	//if( mod(tPlanoZZstring.size(),tamBloque) != 0 )//agregamos la cadena tPlano con el digito mas significativo ( alfabeto.size() )
	//{
		while( mod(ZZ(tPlanoZZstring.size()),ZZ(tamBloque)) != 0 )
		{
			contaux++;
			tPlanoZZstring += to_string(alfabeto.size()-1);
		}
	//}
	cout << "agregamos "<<alfabeto.size()-1 <<" al final de la cadena "<< contaux <<" veces" << endl;

	cout << "tPlanoZZstring: "<< tPlanoZZstring << endl;
	cout << "tam texto a cifrar: "<<tPlanoZZstring.size()<< endl;

	///////////////////////////////////////////////////////////
	//  		EMPEZAMOS CON EL CIFRADO xD                  //
	///////////////////////////////////////////////////////////
	ZZ posC=ZZ(0); // posCifrado
	string tmp;
	//char tmp[dZZ]; // aux que sirve para almacenar el numero a cifrar
	string tmp2; // aux que sirve para aumentar los 0's a completar para el tamBloque+1(tamanio de n)
	string posCstring="";
	ofstream archPlano;
	archPlano.open("Mensaje Cifrado.txt",std::ifstream::binary);
	ZZ tmpZZ ;
	long long cont ,k=0;	
	if( archPlano.is_open())
	{
		for( ; k< tPlanoZZstring.size(); k+=tamBloque)
		{
			//tPlanoZZstring.copy(tmp,tamBloque,k); // copiamos en tmp el substring de tPlanoZZstring[k,k+tamBloque]
			//cout << "k: "<< k << endl;
			cont=0;
			for(long long a=k ; cont<tamBloque; a++)
			{
				tmp+=tPlanoZZstring[a];
				cont++;
				//cout << "entro"<< endl;
			}
			tmpZZ = stoZZ(tmp);
			cout << "cifrar: "<< tmpZZ << endl;
			//cout << "tamanio de cifrado: "<< ZZtos(tmpZZ).size()<< endl;

			posC = cLetra(tmp); // AQUI CIFRAMOSSS XD
			tmp =""; // seteamos tmp 
			//posC = exp(tmpZZ,e,n);
			posCstring = ZZtos(posC);
			// si el tamanio de posC(texto cifrado) es menor que el tam de N(tamBloque+1), entonces llenamos con 0's a la izquierda //
			if( posCstring.size() < tamBloque+1 ) 
			{	
				for (int l=0; l<(tamBloque+1)-posCstring.size(); l++ )
					tmp2+="0";	

				posCstring = tmp2+posCstring; /// dudass ? ----------------------------------------------------------------------------------------------------
				tmp2=""; // seteamos para que el string empieze de nuevo en vacio
			}
	
			cout <<"posCstring: "<<posCstring <<endl;
			archPlano << posCstring;
		}
	
	}
	else
	{
		cout << "Error: No se pudo crear Cifrado.txt " << endl;
		cout << "No se realizo el Cifrado Satisfactamente "<< endl;
		
	}
	archPlano.close();

	cout << " Cifrado Satisfactorio "<< endl;
}

string rsa::convertirRellenarCeros(string cadenaString)
{
	string tPlanoZZstring; //auxiliar, para concatenar c/u de las posiciones de las letras del tPlano

	ll dZZ = to_string(alfabeto.size()-1).size(); // hallamos el tamaño de la letra mas significativa(ultimo elemento) del alfabeto
	cout << "dZZ: "<< dZZ << endl;
	long long aux; // aux que almacenara la posicion en el alfabeto de la letra a cifrar.
	string auxS; // aux que sirve para aumentar los 0's que hagan falta para completar al tamanio de 
	cout << " auxS: "; 
	string cadenaNumeros;
	int i=0;
	for(; i<cadenaString.size()-1;i++) // menos 1, porque en get_file_contents() se utiliza en rdbuf() que lee el archivo y al ultimo ingresa el -1, para no leer ese valor, restamos en 1 al la lectura del string que devuelve get_file_contents()
	{
		aux = alfabeto.find(cadenaString[i]);
		auxS = to_string(aux);
		if ( auxS.size() < dZZ ) //si el tamaño de cadenaString[i] < dZZ, entonces llenar con 0's a la izquierda
		{	
			string tmp(dZZ-auxS.size(),'0');
			auxS += tmp;
		}
		cout << auxS << " " ;
		tPlanoZZstring += auxS ;
	}
	return cadenaNumeros;
}

ZZ rsa::cLetra(string Plano )
{
	ZZ posPlano = stoZZ(Plano);
	ZZ posC; //posC =posCifrado  ; posPlano = posPlano
	ZZ posP, posF;
	ZZ x,ant=ZZ(1) ;
	ZZ j = ZZ(0);
	ZZ ee = ZZ(e);
	//cout << "se murio aqui " << endl;
	//ll posPlano = alfabeto.find(tPlano)+1;
	//out << "posPlano "<<posPlano<<endl;
	bool aux ;
	while(ee > 0){
		x = expoBits(j); // x = 2^j
		aux = ZZtoBool( ee&1 );
		if( aux ){
			//cout << "------------------------"<< endl;
			posP = exp(posPlano,x,n); //resultado parcial
			posF = (posP*ant)%n;
			//posF = mod(posP*ant,n); //resultado final
			ant = posF ; //aqui esta la weada
			//cout << "posP "<< posP<<endl;
			//cout << "posF "<< posF<<endl;
		}
		j++;
		ee >>=1 ;
	}
	posC = posF;


	/* // las siguientes lineas son de verificacion
	posC = mod(posF,alfabeto.size())-1;// porque alfabeto comienza en 0

	cout << "posC "<<posC<<endl;
	tCifrado += alfabeto[(long)posC];
	return tCifrado;
	*/

	return posC;
}

void rsa::descifrar()
{
	cout << "\n\t *****************  descifrado ************* "<< endl;
	ll nTam = ZZtos(n).size(); // longitud de clave n
	cout << "Tamaño de clave n: "<<nTam << endl;
	int dZZ = to_string(alfabeto.size()-1).size(); // encontramos el tamaño del elemento mas significativo del alfabeto

	//////////////////////////////////////////////////////
	/* 					DESCRIFRAMOS					*/
	//////////////////////////////////////////////////////

	string tmp,aux1;
	string tDescifradoTmp;
	//char tDescifradoTmp[nTam];
	string tDescifrado;
	ll tDescifradoInt;

	// usamos ficheros 
	ifstream archCifrado;
	ofstream archDescifrado;
	archCifrado.open("Mensaje Cifrado.txt",ifstream::binary);
	archDescifrado.open("Mensaje Descifrado.txt",ofstream::binary);

	if(archCifrado.is_open() and archDescifrado.is_open())
	{
		getline(archCifrado,tmp); //extraemos la cadena de string Cifrada de archCifrado y lo introducimos en tmp
		//tmp = get_file_contents("Mensaje Cifrado.txt");
		cout <<" cadena a descifrar: "<< tmp << endl;
		int i=0;
		long long k,cont;
		for(; i<tmp.size(); i+=nTam)
		{
			cont =0;
			for(k=i; cont<nTam ; k++)
			{
				//cout << "i: "<< i<< endl;
				tDescifradoTmp+=tmp[k];
				cont++;
			}
			//tmp.copy(tDescifradoTmp, nTam, i); // copiamos en tDescifradoTmp el substring de tmp[i,i+nTam]
			cout << "descifrar(stoi): "<< stoZZ(tDescifradoTmp) <<endl;
			aux1 = ZZtos(dLetra(stoZZ(tDescifradoTmp))); // AQUI DESCIFRAMOSSS 
			tDescifradoTmp ="";
			//cout << "	aux1: "<< aux1 << endl;
			/* En el sgte for , si tDescifradoTmp < nTam-1 , entonces relleanamos de 0's*/
			for(int i=aux1.size(); i<nTam-1; i++ )
				tDescifrado += "0";
			//string tDescifrado ( int(nTam-1-aux1.size()) ,'0');

			tDescifrado += aux1;

			//cout << "tDescifrado: " << tDescifrado << endl;
		}
		cout << "tDescifrado: " << tDescifrado << endl;

		//Buscamos las posciones en el alfabeto , para eso los agrupamos del tamaños de dZZ a dZZ (ver mas: inicio de esta funcion)
		string posD;
		char aux2[dZZ-1];
		//string aux2;
		int j=0;
		long long aa,cont2;
		cout << endl << "dZZ: " << dZZ << endl;
		for(; j<tDescifrado.size(); j+= dZZ)
		{
			/*
			cont2 =0;
			for(aa=j; cont2 < dZZ ;aa++)
			{
				aux2 += tDescifrado[aa];
				cont2++;
			}
			*/
			tDescifrado.copy(aux2,dZZ,j);
			cout << aux2 << " ";
			posD = alfabeto[stoi(aux2)];
			//cout << posD << endl;
			archDescifrado << posD;

		}
		cout << endl;
	}
	else
		cout << "ERROR: No se pudo abrir el archivo Cifrado.txt "<<endl;
	
	archCifrado.close();
	archDescifrado.close();
}

ZZ rsa::dLetra(ZZ posDescifrado) //descifra una letra
{
	string tDescifrado;
	ZZ posD; //posD =posDescifrado 
	ZZ posP, posF; //posP = posParcial ; posF= posFinal
	ZZ x,ant=ZZ(1);
	ZZ j=ZZ(0);
	
	//d= mod(eExtendido(e,fn),fn);
	ZZ dd = d;
	//cout <<"d " <<dd <<endl;
	while(dd>0){
		x = expoBits(j);
		if( mod(dd,ZZ(2))==ZZ(1) ){

			//cout << "------------------------"<< endl;
			posP = exp(posDescifrado,x,n); //resultado parcial
			posF = (posP*ant)%n;
			//posF = mod(posP*ant,n); //resultado final
			ant = posF ; //guardamos la pos Final anterior
			/*
			cout << "posP "<< posP<<endl;
			cout << "posF "<< posF<<endl;
			*/
		}

		j++;
		dd >>=1 ;
	}
	
	posD = posF;
	/*
	posD = mod(posF,alfabeto.size())-1;
	cout <<"posD " << posD << endl;

	tDescifrado += alfabeto[(long)posD];

	return tDescifrado;
	*/
	return posD;
}

ZZ rsa::tRestoChino(ZZ posCifrado)
{
	//cout << " ---------- Resto Chino --------------" << endl;
	ZZ d= ZZ(mod(eExtendido(e,fn),fn));
	ZZ dp = ZZ(mod(d, p-1));
	ZZ dq = ZZ(mod(d, q-1));

	ZZ P = ZZ(n) ; //n=p*q; => nos ahorramos una multiplicacion

	ZZ pi = ZZ(q); //P / p;
	ZZ qi = ZZ(p); //P / q;

	ZZ q_1 = get_q_inicial (pi , p);
	ZZ q_2 = get_q_inicial (qi , q);

	ZZ D_i = mod((exp(posCifrado,dp,P) * pi * q_1), P ) + mod( ( exp(posCifrado,dq,P) * qi * q_2),P);
	D_i = ZZ(mod (D_i,P));

	ZZ posD = ZZ(D_i);

	return posD;
}

ZZ rsa::get_q_inicial(ZZ P,ZZ p_or_q)
{
	ZZ q_i = eExtendido(p_or_q , P); 
	return q_i;
}

vector<ll> cribaEratostenes(ll menor, ll mayor)
{
	vector<ll> primos;
	int i= menor>>1;
	int j= (mayor-menor)>>1;
	//ingresamos los impares entre [menor,mayor]
	for(; i< j+1;i++)
		primos.push_back(2*i+1);

	/*
	int aux=
	while()
	{

	}
	*/
	//primos.push_front(2); //agregamos el 2 
	return primos;
}


bool find(vector<ll>& lista,ll inicio,ll fin,ll& elemento) //BUSQUEDA BINARIA
{
	bool encontrado= false;

	ll centro = (fin-inicio)>>1;
	if(lista[centro] == elemento)
		return true;
	else if(lista[centro] < elemento)
		find(lista,inicio,centro,elemento);
	else //if(lista[centro] > elemento)
		find(lista,centro,fin,elemento);
	return encontrado;
}

/* Modulo			____________
	Tiene la forma | D = d*q +r |
*/
ZZ rsa::mod(ZZ D, ZZ d)
{
	ZZ q = ZZ(D/d);
	ZZ r = ZZ(D-(q*d));
	if ( r< ZZ(0))
	{
		q--;
		r += d;
	}
	return r;
}

/*
ZZ rsa::exp(ZZ a, ZZ b, ZZ m)
{
	//cout << 1;
	ZZ res;
    if(b==0)
    	return ZZ(1);
    res=exp(a,b>>1,m);
    res=mod((res*res),m);
    bool val = ZZtoBool(b&ZZ(1)) ;
    if(val) //verificamos si es impar
    	res=(res*a)%m;
    return res;
}
*/
ZZ rsa::exp(ZZ  a, ZZ p, ZZ n)
	{
	ZZ  y;
	y = ZZ(1);
	while (p!=ZZ(0))
	{
      if ((p&1)==1)
		y = mod((y * a) ,n);

      a = mod((a * a),n);
      p = p >> 1;
	}

	return y;
	}
/*
ll rsa::expBinaria(ll a, ll b, ll m)
{
	ll res=ll(1); 
	ll x = mod(a,m);
	while(b>0 ){
		//cout << 1 ;
		if(m&ll(1)){ // si es impar,osea el ultimo bit de "n" es 1
			// cambié m por n , nose porque , si algo sale mall , este quiza es el error 
			res = mod(res*x,m);
			x = mod(x*x,m);
			b >>= 1;
		}
	}
	return res;
}
*/

/*
bool rsa::primo(ZZ n)
{

	if ( fermat(n))
	{
		if ( millerRabin(n) )
		{
			return true;
		}
	}
	return false;
}

*/

bool rsa::millerRabin(ZZ n)
{

}


bool rsa::fermat(ZZ num)
{	/*
	bool esPrimo = true ;
	vector<ZZ> testigos; //= {2,3,5,7}; // y mas ..
	testigos.push_back(ZZ(2));
	testigos.push_back(ZZ(3));
	testigos.push_back(ZZ(5));
	testigos.push_back(ZZ(7));
	for(int i=0; i<4 ; i++)
	{
			if (exp(testigos[i],num-1,num) ==1 && mod(num,testigos[i])!=0 )
			{
				return true;
			}
			//else
			//	cout << testigos[i]<<endl;
	}
	return false ;
	*/
}

ZZ rsa::expoBits(ZZ nbits)
{
	ZZ res=ZZ(1);
	ZZ i=ZZ(0);
	for(; i<nbits;i++)
		res <<= 1;
	return res;
}

ZZ rsa::mcd( ZZ a , ZZ b ) 
{
	ZZ aux = ZZ(1) ;
	ZZ tmp; 

	while( a % 2 == 0 and b %2 == 0 )
	{
	//cout << " 2 " << endl;
		a >>= 1 ; 
		b >>= 1 ; 
		aux <<= 1 ; 
	}

	while ( a != 0 )
	{
	//cout << " 3 " << endl;
		if ( mod(a, ZZ(2)) == 0)
			a >>= 1 ; 
		else if ( mod(b, ZZ(2)) == 0 )
			b >>= 1; 
		else { //3er caso : a y b son impares			
			tmp = abs(a-b); 
			tmp >>= 1 ; 
			if (a >= b )
				a = tmp; 
			else
				b = tmp;
		}
	}

	return aux*b;
}

ZZ rsa::eExtendido(ZZ a ,ZZ b)
{ 
	ZZ r1 , r2, s1, s2 , t1, t2, r,s,t,q;
	r1=a ; r2=b ; s1 = ZZ(1) ; s2 = ZZ(0)  ; t1 = ZZ(0) ; t2 = ZZ(1) ;

	while( r2> ZZ(0))
	{
		q = r1/r2;
		r = r1 -(q*r2);
		r1 = r2 ; r2 = r ;

		s= s1 -(q*s2);
		s1 = s2 ; s2 = s ;

		t = t1 -(q*t2) ;
		t1 = t2 ; t2 = t ; 
	}
	return s1;
}

string rsa::get_file_contents(const char *filename)
{
  ifstream in(filename, std::ios::in | std::ios::binary);
  if (in)
  {
    return(string( (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>() ));
  }
}
	/************************************************************************************************************/
	//			 				En esta parte hacemos las conversiones 						

string rsa::ZZtos(ZZ num)
{
	stringstream conv;
	conv << num;
	return conv.str();
}

ZZ rsa::stoZZ(string num)
{
	ZZ conv(INIT_VAL , num.c_str());
	return conv;
}


bool rsa::ZZtoBool(ZZ number)
{
	stringstream conv;
	conv << number;
	string tmp = conv.str();
	return stoi(tmp);
}
