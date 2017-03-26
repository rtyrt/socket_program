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
#include <list>
#include <arpa/inet.h>
#include </opt/local/include/openssl/ssl.h>
#include </opt/local/include/openssl/err.h>

using namespace std;
struct Client_Account
{
	string name;
	int account_balance;
};
struct Online_Client
{
	int num;
	string name;
	string ip_addr;
	string portNum;
};

void client_quit(int login_client_num, struct Online_Client online_client[], int online_num){
	cout << endl << "-> Client quit: " << online_num-1 ;
	cout << " --- " << online_client[login_client_num].name << " " << online_client[login_client_num].ip_addr << " " << online_client[login_client_num].portNum << " --- \n" << endl;

	online_client[login_client_num].name = "";
	online_client[login_client_num].ip_addr = "";
	online_client[login_client_num].portNum = "";
}
void client_join(int login_client_num, struct Online_Client online_client[], string temp_client_name, string temp_client_ip, string temp_port_num, int online_num ){
	online_client[login_client_num].name = temp_client_name;
	online_client[login_client_num].ip_addr = temp_client_ip;
	online_client[login_client_num].portNum = temp_port_num;

	cout << endl << "-> Client join: " << online_num ;
	cout << " --- " << online_client[login_client_num].name << " "<<online_client[login_client_num].ip_addr << " " << online_client[login_client_num].portNum << " --- \n" << endl;
}

list<SSL *>sockets;
pthread_mutex_t thread_lock;
struct sockaddr_in server_addr, client_addr;

struct Client_Account client[1024];
struct Online_Client online_client[1024];
int client_num = 0;
int login_client_num = 0;
int online_num = 0;

void* worker_pool(void* data){
	while (1){
		pthread_mutex_lock(&thread_lock);
		if (sockets.size() > 0)
		{
			SSL *this_ssl = sockets.front();
			int this_sd = SSL_get_fd(this_ssl);
			
			sockets.pop_front();
			pthread_mutex_unlock(&thread_lock);

			fd_set active_fd_set;
			FD_ZERO(&active_fd_set);
			FD_SET(this_sd, &active_fd_set);

			timeval tv;
			tv.tv_sec = 0;
			tv.tv_usec = 0;

			bool online = 1;
			bool login = 0;

			if (select(this_sd+1, &active_fd_set, NULL, NULL, &tv) > 0)
			{
				string input;
				
				//online
				char responce_buffer[1024];
				
				bool regi = 0;
				string this_client_name = "";

				while(online) {
					memset(responce_buffer, 0, 1024);
					
					SSL_read(this_ssl, responce_buffer, 1023);
					// recv(this_sd,(char *) &responce_buffer, 1023, 0);

					string temp_resp_str(responce_buffer);

					if (temp_resp_str == "")
					{
						input = "200 Empty Input";
						SSL_write(this_ssl, input.c_str(), input.length()); 
						// send(this_sd, input.c_str(), input.length(), 0);
					}

					cout << "-> Message From Client: " << temp_resp_str << endl;
		
				//REGISTER
					if (temp_resp_str.substr(0,8) == "REGISTER" )
					{
						bool isclient = 0;
						int find_num = temp_resp_str.find("#",9);
						for (int i = 0; i < client_num; ++i)
							if (temp_resp_str.substr(9, find_num-9) == client[i].name)
								isclient = 1;

						if (!isclient)
						{
							input = "100 OK";
							client[client_num].name = temp_resp_str.substr(9, find_num-9);
							client[client_num].account_balance = atoi(temp_resp_str.substr(find_num+1).c_str());
							client_num++;
							regi = 1;
							SSL_write(this_ssl, input.c_str(), input.length());  
							// send(this_sd, input.c_str(), input.length(), 0);
						}
						if (isclient)
						{
							input = "210 FAIL";
							SSL_write(this_ssl, input.c_str(), input.length());  
							// send(this_sd, input.c_str(), input.length(), 0);
						}
					}
				//LIST
					else if (temp_resp_str == "List")
					{
						for (int i = 0; i < 1024; ++i)
							if (online_client[i].name == this_client_name)
								login_client_num = online_client[i].num;
						input = "\nAccountBalance:" + to_string(client[login_client_num].account_balance) + "\nNumber of users:" + to_string(online_num) + "\n" ;
						for (int i = 0; i < 1024; ++i)
							if (online_client[i].name != "")
								input += online_client[i].name + "#" + online_client[i].ip_addr + "#" + online_client[i].portNum + "\n"; 

						SSL_write(this_ssl, input.c_str(), input.length()); 
						// send(this_sd, input.c_str(), input.length(), 0);
					}
				//EXIT
					else if (temp_resp_str == "Exit")
					{
						input = "Bye";
						for (int i = 0; i < 1024; ++i)
							if (online_client[i].name == this_client_name)
								login_client_num = online_client[i].num;
						
						client_quit(login_client_num, online_client, online_num);
						online_num -= 1;

						SSL_write(this_ssl, input.c_str(), input.length()); 
						// send(this_sd, input.c_str(), input.length(), 0);
						online = 0;
						
					}
				//TRANSACTION
					else if (temp_resp_str.substr(0,5) == "TRANS")
					{
						temp_resp_str = temp_resp_str.substr(6);
						int find_pos = temp_resp_str.find("#");
						string payer_name = temp_resp_str.substr(0,find_pos);
						int amount = atoi(temp_resp_str.substr(find_pos+1,temp_resp_str.find("#", find_pos+1)-find_pos-1).c_str());
						string payee_name = temp_resp_str.substr(temp_resp_str.find("#", find_pos+1)+1);

						for (int i = 0; i < client_num; ++i)
							if (client[i].name == payer_name)
								client[i].account_balance  -= amount;
								

						for (int i = 0; i < client_num; ++i)
							if (client[i].name == payee_name)
								client[i].account_balance += amount;

					}

				//LOGIN
					else 
					{
						bool isclient = 0;
						bool usedport = 0;
						bool client_online = 0;
						string temp_client_name = temp_resp_str.substr(0,temp_resp_str.find("#"));
						string temp_client_ip = inet_ntoa(client_addr.sin_addr);
						string temp_port_num = temp_resp_str.substr(temp_resp_str.find("#")+1);


						for (int i = 0; i < client_num; ++i)
							if (temp_client_name == client[i].name)
								isclient = 1;
						for (int i = 0; i < 1024; ++i)
							if (temp_port_num == online_client[i].portNum)
								usedport = 1;
						for (int i = 0; i < 1024; ++i)
							if (temp_client_name == online_client[i].name)
								client_online = 1;
				
					//NO REGISTER TRY TO LOGIN	
						if (!isclient)
						{
							input = "220 AUTH_FAIL";
							SSL_write(this_ssl, input.c_str(), input.length()); 
							// send(this_sd, input.c_str(), input.length(), 0);
						}
					//REGISTER TRY TO USE OTHER NAME LOGIN IN
						else if (!isclient && !regi)
						{
							input = "230 REGI_FAIL";
							SSL_write(this_ssl, input.c_str(), input.length());  
							// send(this_sd, input.c_str(), input.length(), 0);
						}
					//REGISTER BUT USE SAME USER NAME TO LOGIN	
						else if (isclient && client_online)
						{
							input = "240 USER_ONLINE";
							SSL_write(this_ssl, input.c_str(), input.length()); 
							// send(this_sd, input.c_str(), input.length(), 0);
						}
					//REGISTER AND USE SAME NAME BUT USED PORT LOGIN IN
						else if (isclient && usedport)
						{
							input = "250 USED_PORT";
							SSL_write(this_ssl, input.c_str(), input.length()); 
							// send(this_sd, input.c_str(), input.length(), 0);
						}
					//REGISTER AND USE SAME NAME LOGIN IN
						else if (isclient)
						{
							online_num += 1;
							login_client_num = online_num-1;
							online_client[login_client_num].num = login_client_num;
							this_client_name = temp_client_name;

							client_join(login_client_num, online_client, temp_client_name, temp_client_ip, temp_port_num, online_num);

							input = "\nAccount Balance:" + to_string(client[login_client_num].account_balance) + "\nNumber of users:" + to_string(online_num) + "\n" ;
							for (int i = 0; i < 1024; ++i)
								if (online_client[i].name != "")
									input += online_client[i].name + "#" + online_client[i].ip_addr + "#" + online_client[i].portNum + "\n"; 
							
							SSL_write(this_ssl, input.c_str(), input.length()); 
							// send(this_sd, input.c_str(), input.length(), 0);
						}
					}
				}
			}

			if (!online )
			{
				// SSL_free(ssl);        // release connection state
				close(this_sd);
				// SSL_CTX_free(ctx);        // release context
			}
				
			else
			{
				pthread_mutex_lock(&thread_lock);
				sockets.push_back(this_ssl);
				pthread_mutex_unlock(&thread_lock);
			}
			
		}
		else
		{
			pthread_mutex_unlock(&thread_lock);
			sleep(10);
		}
	}
}

int main(int argc, char *argv[]) {

	if (argc < 2)
	{
		cout << "Input code has to be: " + string(argv[0]) + " server_port_number\n" ;
		exit(0);
	}
	int port_num = atoi(argv[1]);

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

	//set socket
	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0)
	{
		cout << "Socket opening isn't successful.\n";
		exit(0);
	}

	//set server
	memset((char *) &server_addr, 0, sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(port_num);

	//bind
	if (bind(sd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
	{
		cout << "Error occurs when binding.\n";
		exit(0);
	}

	//listen
	listen(sd, 5);
	
	//thread, 8 workers
	pthread_mutex_init(&thread_lock, NULL);
	pthread_t worker[15];
	for (int i = 0; i < 15; ++i)
		pthread_create(&worker[i], NULL, worker_pool, NULL);

	socklen_t client_length = sizeof(client_addr);

	while (1){
		//accept
		int new_sd = accept(sd, (struct sockaddr *) &client_addr, &client_length);
		if (new_sd < 0)
		{
			cout << "Error occurs when accepting.\n";
			exit(0);
		}

    	SSL *ssl;
    	ssl = SSL_new(ctx);

		SSL_set_fd(ssl, new_sd);
		if (!SSL_accept(ssl))
		{
		 	cout << "SSL connection is not successful.\n";
			exit(0);
		}  

		string success_inform = "successful connection";
		SSL_write(ssl, success_inform.c_str(), success_inform.length()); 
		// send(new_sd, success_inform.c_str(), success_inform.length(), 0);

		pthread_mutex_lock(&thread_lock);
		sockets.push_back(ssl);
		pthread_mutex_unlock(&thread_lock);
	}

	// SSL_free(ssl);        // release connection state
	close(sd);
	SSL_CTX_free(ctx);        // release context

	return 0;
}