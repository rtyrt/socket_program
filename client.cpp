#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <cctype>
#include </opt/local/include/openssl/ssl.h>
#include </opt/local/include/openssl/err.h>

using namespace std;
struct Online_Client
{
	string name;
	string ip_addr;
	string portNum;
};

int this_port_num;
struct Online_Client online_client[1024];

void check_online_client(string resp_str){
	for (int i = 0; i < 1024; ++i)
	{
		online_client[i].name = "";
		online_client[i].ip_addr = "";
		online_client[i].portNum = "";
	}
	
	int temp_pos;
	for(int i = 0; i < 2;i++){
		temp_pos = resp_str.find("\n",1);
		resp_str = resp_str.substr(temp_pos+1);
	}
	int counter = 0;
	while(resp_str != ""){

		online_client[counter].name = resp_str.substr(0,resp_str.find("#"));
		resp_str = resp_str.substr(resp_str.find("#")+1);
		
		online_client[counter].ip_addr = resp_str.substr(0,resp_str.find("#"));
		resp_str = resp_str.substr(resp_str.find("#")+1);
		
		online_client[counter].portNum = resp_str.substr(0,resp_str.find("#"));
		resp_str = resp_str.substr(resp_str.find("\n")+1);
			
		counter ++;
	}
}

void* transaction_worker(void* data){
	SSL* server_ssl = (SSL*) data;

	//SSL part
	SSL_library_init();
	SSL_load_error_strings();

	const SSL_METHOD *meth;
   	SSL_CTX *ctx;

	meth = TLSv1_method();
	ctx = SSL_CTX_new(meth);
	char CertFile[] = "/Users/Vic/Desktop/mycert.pem";
	char KeyFile[] = "/Users/Vic/Desktop/mykey.pem";

	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )	//set the local certificate from CertFile
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ) 	//set the private key from KeyFile
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
	if ( !SSL_CTX_check_private_key(ctx) )		 //verify private key 
	{
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }

	struct sockaddr_in serv_addr, cli_addr;

	int client_serv_sd = socket(AF_INET, SOCK_STREAM, 0);
	if (client_serv_sd < 0)
	{
		cout << "Socket opening isn't successful.\n";
		exit(0);
	}

	//set server
	memset((char *) &serv_addr, 0, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(this_port_num);

	//bind
	if (bind(client_serv_sd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		cout << "Error occurs when binding.\n";
		exit(0);
	}

	//listen
	listen(client_serv_sd, 5); 

	socklen_t cli_length = sizeof(cli_addr);

	while (1){
		int client_sd = accept(client_serv_sd, (struct sockaddr *) &cli_addr, &cli_length);
		if ( client_sd < 0)
		{
			cout << "Error occurs when accepting.\n";
			exit(0);
		}
		
		SSL *client_ssl;
		client_ssl = SSL_new(ctx);

		SSL_set_fd(client_ssl, client_sd);
		if (!SSL_accept(client_ssl))
		{
		 	cout << "SSL connection is not successful.\n";
			exit(0);		
		}  
				
		//transaction
		char responce_buffer[1024];
		memset(responce_buffer, 0, 1024);
		SSL_read(client_ssl, responce_buffer, 1023);

		string temp_resp_str = responce_buffer;
		temp_resp_str = "TRANS#" + temp_resp_str;

		SSL_write(server_ssl, temp_resp_str.c_str(), temp_resp_str.length());
	}
	
	

	close(client_serv_sd);
	pthread_exit(0);
}


int main (int argc, char *argv[]){
 
	// situation with wrong input code
	if (argc < 3)
	{
		cout << "Input code has to be: " + string(argv[0]) + "server_IP port_number\n" ;
		exit(0);
	}
	//change portnumber into number
	int port_num;
	port_num = atoi(argv[2]);

	//get server_ip
	struct hostent *server_ptr;
	server_ptr = gethostbyname(argv[1]);
	if (server_ptr == NULL)
	{
		cout << "We cannot find the host.\n";
		exit(0);
	}

	//SSL part
	SSL_library_init();
	SSL_load_error_strings();

	const SSL_METHOD *meth;
   	SSL_CTX *ctx;

	meth = TLSv1_method();
	ctx = SSL_CTX_new(meth);
	char CertFile[] = "/Users/Vic/Desktop/mycert.pem";
	char KeyFile[] = "/Users/Vic/Desktop/mykey.pem";

	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )	//set the local certificate from CertFile
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ) 	//set the private key from KeyFile
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
	if ( !SSL_CTX_check_private_key(ctx) )		 //verify private key 
	{
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }

    SSL *server_ssl;
	server_ssl = SSL_new(ctx);
	
	//sd = socket_descriptor
	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0)
	{
		cout << "Wrong socket number.\n";
		exit(0);
	}

	struct sockaddr_in server_addr;

	memset((char *) &server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	memmove((char *) &server_addr.sin_addr.s_addr,(char *) server_ptr->h_addr, server_ptr->h_length);
	server_addr.sin_port = htons(port_num);

	if (connect(sd,(struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
	{
		cout << "Connection is not successful.\n";
		exit(0);
	}

	SSL_set_fd(server_ssl, sd);
	if (!SSL_connect(server_ssl))
	 {
	 	cout << "SSL connection is not successful.\n";
		exit(0);
	 }   

	string input;
	string myName;

	char responce_buffer[1024];
	memset(responce_buffer, 0, 1024);

	SSL_read(server_ssl, responce_buffer, sizeof(responce_buffer));
	// recv(sd,(char *) &responce_buffer, 1023, 0);
	cout << responce_buffer << endl;

	bool login = 1;
	bool regi = 1;
	string register_name, original_account_amount, login_name, login_portNum;

	while(regi) {
		cout << "Enter 1 for Register, 2 for Login: ";
		cin >> input;

		bool error_input = 0;
		if (input == "1")
		{
			bool isNum = 1;
			cout << "Enter the name to register: ";
			cin >> register_name;
			cout << "Enter the original account amount: ";
			cin >> original_account_amount;

			//Check if the account amount is a real number
			for (int i = 0; i < original_account_amount.length(); ++i)
				if (!isdigit(original_account_amount[i]))
					isNum = 0;

			if (isNum)
				input = "REGISTER#" + register_name + "#" + original_account_amount; 
			else
			{
				error_input = 1;
				cout << "The original account amount is a number." << endl;
			}	
		}
		else if (input == "2")
		{
			bool isNum = 1;
			cout << "Enter your name: ";
			cin >> login_name;
			cout << "Enter port number: ";
			cin >> login_portNum;

			myName = login_name;
			this_port_num = atoi(login_portNum.c_str());
			
			for (int i = 0; i < login_portNum.length(); ++i)
				if (!isdigit(login_portNum[i]))
					isNum = 0;
			if (isNum)
				input = login_name + "#" + login_portNum;
			else
			{
				error_input = 1;
				cout << "The port number is invalid." << endl;
			}
		}		
		else
			error_input = 1;
		
		if (!error_input)
		{
			SSL_write(server_ssl, input.c_str(), input.length()); 
			// send(sd, input.c_str(), input.length(), 0);
			memset(responce_buffer, 0, 1024);

			SSL_read(server_ssl, responce_buffer, 1023);
			// recv(sd,(char *) &responce_buffer, 1023, 0);
			cout << responce_buffer <<endl;
			
			if (responce_buffer[0] != '1' && responce_buffer[0] != '2')
			{	
				regi = 0;
				check_online_client(string(responce_buffer));
			}
		}
		
	}
	cout << "Login Successfully\n";
	pthread_t worker;
	    pthread_create(&worker, NULL, transaction_worker, server_ssl);

	while(login) {

		
		cout << "Enter 1 to ask for the latest list, 2 to transaction 8 to exit: ";
		cin >> input;

		bool error_input = 0;
		bool transaction_input = 0;
		if (input == "1")
			input = "List";
		else if (input == "2"){

			bool isNum = 1;		
			string payer = myName;
			string amount;
			string payee;
			cout << "Enter the user you are going to pay: ";
			cin >> payee;
			cout << "Enter the transaction amount: ";
			cin >> amount;

			for (int i = 0; i < amount.length(); ++i)
			{	
				if (!isdigit(amount[i]))
				{	
					isNum = 0;
					error_input = 1;
					cout << "The amount must be an integer.\n";
				}
			}

			if (isNum)
				input = payer + "#" + amount + "#" + payee;
			else
				error_input = 1;

			int temp_client_num = -1;
			for (int i = 0; i < 1024; ++i)
				if (payee == online_client[i].name)
					temp_client_num = i;

			if (temp_client_num == -1)
			{
				error_input = 1;
				cout << "The user you want to pay isn't online or isn't exist.\n";
			}



			if (!error_input)
			{	
				int temp_port_num = atoi(online_client[temp_client_num].portNum.c_str()); 
				string temp_ip = online_client[temp_client_num].ip_addr;
			
				struct hostent *client_ptr;
				client_ptr = gethostbyname(temp_ip.c_str());

				struct sockaddr_in client_addr;
				
				SSL *client_ssl;
				client_ssl = SSL_new(ctx);

				int client_sd = socket(AF_INET, SOCK_STREAM, 0);
				if (client_sd < 0)	
				{
					cout << "Wrong socket number.\n";
					exit(0);
				}

				memset((char *) &client_addr, 0, sizeof(client_addr));
				client_addr.sin_family = AF_INET;
				memmove((char *) &client_addr.sin_addr.s_addr,(char *) client_ptr->h_addr, client_ptr->h_length);
				client_addr.sin_port = htons(temp_port_num);

				SSL_set_fd(client_ssl, client_sd);
				if (!SSL_connect(client_ssl))
				{
					cout << "SSL connection is not successful.\n";
					exit(0);
				} 	

				if (connect(client_sd,(struct sockaddr *) &client_addr, sizeof(client_addr)) < 0)
				{	
					cout << "Connection is not successful. \n";
					exit(0);
				}
				SSL_write(client_ssl, input.c_str(), input.length()); 
				close(client_sd);
				transaction_input = 1;
			}
		}
		else if (input == "8")
		{
			input = "Exit";
			login = 0;
		}
		else
			error_input = 1;
		
		if (!error_input && !transaction_input)
		{
			SSL_write(server_ssl, input.c_str(), input.length()); 
			// send(sd, input.c_str(), input.length(), 0);
			memset(responce_buffer, 0, 1024);
			SSL_read(server_ssl, responce_buffer, 1023);
			// recv(sd,(char *) &responce_buffer, 1023, 0);
			cout << responce_buffer <<endl;
			if (input == "List")
			{
				check_online_client(string(responce_buffer));
			}
		}
	}
	
	SSL_free(server_ssl);        // release connection state
	close(sd);
	SSL_CTX_free(ctx);        // release context

	return 0;

}