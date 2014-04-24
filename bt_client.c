#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>

#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"

int main (int argc, char * argv[]){

  bt_args_t bt_args;
  be_node * node; // top node in the bencoding
  int i;
  char ipv4_addr[INET_ADDRSTRLEN];
  int sock;
  char * handshake;
  char * handshakeToReceive;
  
  parse_args(&bt_args, argc, argv);


  if(bt_args.verbose){
    printf("Args:\n");
    printf("verbose: %d\n",bt_args.verbose);
    printf("save_file: %s\n",bt_args.save_file);
    printf("log_file: %s\n",bt_args.log_file);
    printf("torrent_file: %s\n", bt_args.torrent_file);

    for(i=0;i<MAX_CONNECTIONS;i++){
      if(bt_args.peers[i] != NULL)
        print_peer(bt_args.peers[i]);
    }

    
  }
  
  bt_args.logFile = fopen(bt_args.log_file, "w");
  if(bt_args.logFile == NULL) {
	  perror("Error opening log file");
	  exit(-1);
  }

  //read and parse the torent file
  node = load_be_node(bt_args.torrent_file);
  bt_args.bt_info = malloc(sizeof(bt_info_t));				// referenced from http://stackoverflow.com/a/9561326
  //bt_args.bt_info = NULL;
  parse_bt_info(&bt_args, bt_args.bt_info, node, "");
  
  if(!bt_args.saveFileFlag) {
	fprintf(bt_args.logFile, "Save file name not specified\n");
	fprintf(bt_args.logFile, "Using default name: %s\n", bt_args.bt_info->name);
	strncpy(bt_args.save_file, bt_args.bt_info->name, FILE_NAME_MAX);
  }
 
  if(bt_args.verbose){
    be_dump(node);
  }
 
  if(bt_args.ipFlag)
	  strcpy(ipv4_addr, bt_args.ipAddr);
  
  for(i = INIT_PORT; i < (MAX_PORT + 1); i++) {
	  if((sock = listen_mode(&bt_args, i, ipv4_addr, bt_args.ipFlag)) > 0) {
		  bt_args.port = i;
          break;
	  }
  }

  fprintf(bt_args.logFile, "IP address from interface: %s\n", ipv4_addr);
  calc_id(ipv4_addr, bt_args.port, (char *) bt_args.id);				// calculate own id
  //handshake = (char *) malloc (68);
  //strncpy(handshake, generateHandshake(&bt_args), 68);
  handshake = generateHandshake(&bt_args);
  fprintf(bt_args.logFile, "Handshake string: %s\n", handshake);
  fprintf(bt_args.logFile, "Info hash: %s\n", handshake + 28);
  fprintf(bt_args.logFile, "ID: %s\n", handshake + 48);
  //printf("ID: %s\n", bt_args.id);
  fprintf(bt_args.logFile, "ID in hex:\n");
  for(i = 0; i < ID_SIZE; i++){
	  fprintf(bt_args.logFile, "%02x", bt_args.id[i]);
  }
  fprintf(bt_args.logFile, "\n");
  
  if(!bt_args.pFlag) {		// server mode
	  printf("Server started\n");
	  fprintf(bt_args.logFile, "Server started\n");
	  fprintf(bt_args.logFile, "IP Address: %s\n", ipv4_addr);
	  fprintf(bt_args.logFile, "Port: %d\n", bt_args.port);
	  server_mode(&bt_args, sock, handshake);
	  //calc_id(ipv4_addr, bt_args.port, bt_args.id);
	  //printf("ID: %s\n", bt_args.id);
  }

  else {
	  printf("Client mode\n");
	  fprintf(bt_args.logFile, "Client mode\n");
  	  fprintf(bt_args.logFile, "IP Address: %s\n", ipv4_addr);
  	  fprintf(bt_args.logFile, "Port: %d\n", bt_args.port);
  	  for(i = 0; i < MAX_CONNECTIONS; i++){
  		  if((bt_args.peers[i] != NULL)){
  			  print_peer(bt_args.peers[i]);
  			  int sock = client_mode(bt_args.peers[i], &bt_args, handshake);
  			  break;
  		  }
	}
  }
  
  //main client loop
 // printf("Starting Main Loop\n");
 // while(1){

	  
  //  server_mode(&bt_args, sock, handshake);
	  //try to accept incoming connection from new peer
       
    
    //poll current peers for incoming traffic
    //   write pieces to files
    //   udpdate peers choke or unchoke status
    //   responses to have/havenots/interested etc.
    
    //for peers that are not choked
    //   request pieaces from outcoming traffic

    //check livelenss of peers and replace dead (or useless) peers
    //with new potentially useful peers
    
    //update peers, 

 // }

  return 0;
}
