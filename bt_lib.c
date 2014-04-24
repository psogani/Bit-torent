#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <openssl/sha.h> //hashing pieces

#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"



void calc_id(char * ip, unsigned short port, char *id){
  char data[256];
  int len;
  
  //format print
  len = snprintf(data, 256, "%s%u", ip, port);

  //id is just the SHA1 of the ip and port string
  SHA1((unsigned char *) data, len, (unsigned char *) id);
  
  //printf("Data: %s\n", data);
  //printf("ID: %s\n", id);

  return;
}


/**
 * init_peer(peer_t * peer, int id, char * ip, unsigned short port) -> int
 *
 *
 * initialize the peer_t structure peer with an id, ip address, and a
 * port. Further, it will set up the sockaddr such that a socket
 * connection can be more easily established.
 *
 * Return: 0 on success, negative values on failure. Will exit on bad
 * ip address.
 *   
 **/
int init_peer(peer_t *peer, char * id, char * ip, unsigned short port){
    
	//printf("IP: %s & port: %d\n", ip, port);
	struct hostent * hostinfo;
	//set the host id and port for referece
	memcpy(peer->id, id, ID_SIZE);
	peer->port = port;
    
	//get the host by name
	if((hostinfo = gethostbyname(ip)) ==  NULL) {
		perror("gethostbyname failure, no such host?");
		herror("gethostbyname");
		exit(1);
	}
  
	//zero out the sock address
	bzero(&(peer->sockaddr), sizeof(peer->sockaddr));
      
	//set the family to AF_INET, i.e., Iternet Addressing
	peer->sockaddr.sin_family = AF_INET;
    
	//copy the address to the right place
	bcopy((char *) (hostinfo->h_addr), (char *) &(peer->sockaddr.sin_addr.s_addr), hostinfo->h_length);
    
	//encode the port
	peer->sockaddr.sin_port = htons(port);
  
	strncpy(peer->ip, inet_ntoa(peer->sockaddr.sin_addr), INET_ADDRSTRLEN);
	//fprintf(bt_args->logFile, "Peer initialized with IP %s and port %d\n", peer->ip, ntohs(peer->sockaddr.sin_port));
  
	peer->socketDescriptor = -1;
  
	return 0;
}

/**
 * print_peer(peer_t *peer) -> void
 *
 * print out debug info of a peer
 *
 **/
void print_peer(peer_t *peer){
  int i;

  if(peer){
    //printf("peer: %s:%u ", inet_ntoa(peer->sockaddr.sin_addr), peer->port);
	printf("peer: %s:%u ", peer->ip, peer->port);
    printf("id: ");
    for(i=0;i<ID_SIZE;i++){
      printf("%02x",peer->id[i]);
    }
    printf("\n");
  }
}


int parse_bt_info(bt_args_t * bt_args, bt_info_t * bt_info, be_node * node, char *keyToCompare) {

	//printf("Key to compare: %s\n", keyToCompare);
	int i;
	char * hash;
	int sizeOfHash = 20;

	if(node->type == BE_STR) {
		//printf("Inside BE_STR\n");
		if (strcmp(keyToCompare, "announce") == 0) {
			//printf("Node->Val.s: %s\n", node->val.s);
			//bt_info->announce = (char *) malloc(strlen(node->val.s));
			//memset(bt_info->announce, 0, sizeof(bt_info->announce));
			//printf("BT_INFO->ANNOUNCE: %s", bt_info->announce);
			strncpy(bt_info->announce, node->val.s, strlen(node->val.s));
			//printf("success\n");
			bt_info->announce[strlen(node->val.s)] = '\0';
			//printf("Announce: %s\n", bt_info->announce);
		}

		if (strcmp(keyToCompare, "name") == 0) {
			//printf("node->val.s: %s\n", node->val.s);
			//printf("Strlen of node->val.s: %zd", strlen(node->val.s));
			strncpy(bt_info->name, node->val.s, strlen(node->val.s));
			bt_info->name[strlen(node->val.s)] = '\0';
			//printf("Name: %s\n", bt_info->name);
			bt_info->info_hash = malloc(sizeOfHash);					// allocate memory for info_hash
			SHA1((unsigned char *) bt_info->name, strlen(bt_info->name), bt_info->info_hash);
		}

		if (strcmp(keyToCompare, "pieces") == 0) {
			bt_info->num_pieces = be_str_len(node)/20;
			if(bt_args->verbose)
				printf("Number of Pieces: %d\n", bt_info->num_pieces);
			fprintf(bt_args->logFile, "Number of Pieces: %d\n", bt_info->num_pieces);
			bt_info->piece_hashes = malloc(bt_info->num_pieces*sizeof(unsigned char*));

			for (i = 0; i < bt_info->num_pieces; i++) {
				hash = malloc(sizeOfHash);
				memcpy(hash, node->val.s + i * sizeOfHash, sizeOfHash);
				bt_info->piece_hashes[i] = hash;
			}
		}
	}
	
	else if(node->type == BE_INT) {
		//printf("Inside BE_INT\n");
		if (strcmp(keyToCompare, "length") == 0) {
			bt_info->length = node->val.i;
			//printf("Length: %d\n", bt_info->length);
		}
	
		if (strcmp(keyToCompare, "piece length") == 0) {
			bt_info->piece_length = node->val.i;
			//printf("Piece Length: %d\n", bt_info->piece_length);
		}
	}
	
	else if(node->type == BE_DICT) {
		//printf("Inside BE_DICT\n");
		for (i = 0; node->val.d[i].val; i++) {
			//printf("Inside for: i = %d\n", i);
			parse_bt_info(bt_args, bt_info, node->val.d[i].val, node->val.d[i].key);
		}
	}

	else
		printf("Error parsing torrent file\n");
	
	return 0;
}

int listen_mode(bt_args_t * bt_args, unsigned short port, char * ipv4, int ipFlag) {
	struct hostent * hostinfo;
	struct sockaddr_in destaddr;
	int sockfd;
	struct ifreq ifr;
	int rc, on = 1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd == -1) {
		perror("Error opening socket");
		fprintf(bt_args->logFile, "Error opening socket");
		return -1;
	}
	
	// referenced from http://publib.boulder.ibm.com/infocenter/iseries/v5r3/index.jsp?topic=%2Frzab6%2Frzab6xnonblock.htm
	rc = setsockopt(sockfd, SOL_SOCKET,  SO_REUSEADDR, (char *)&on, sizeof(on));
	if (rc < 0) {
		perror("setsockopt() failed");
		fprintf(bt_args->logFile, "setsockopt() failed"); 
		close(sockfd);
		exit(-1);
	}

	rc = ioctl(sockfd, FIONBIO, (char *)&on);
	if (rc < 0) {
		perror("ioctl() failed");
		fprintf(bt_args->logFile, "ioctl() failed\n");
		close(sockfd);
		fclose(bt_args->logFile);
		exit(-1);
	}
	
	if(!ipFlag) {
		// get IPV4 address associated with eth0 / em1
		// referenced from http://www.geekpage.jp/en/programming/linux-network/get-ipaddr.php
		ifr.ifr_addr.sa_family = AF_INET;
		//strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
		strncpy(ifr.ifr_name, "em1", IFNAMSIZ-1);		// em1 interface for burrow machines
		ioctl(sockfd, SIOCGIFADDR, &ifr);
		strcpy(ipv4, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
		//printf("IP Address: %s\n", ipv4);
	}
	
	if(!bt_args->pFlag) {
		if(!(hostinfo = gethostbyname(ipv4))) {
			fprintf(stderr, "ERROR: Invalid host name\n");
			fprintf(bt_args->logFile, "Error invalid hostname\n");
			return -1;
		}
		
		destaddr.sin_family = AF_INET;	
		bcopy((char *) hostinfo->h_addr, (char *) &destaddr.sin_addr.s_addr, hostinfo->h_length);
	
		// copy port
		destaddr.sin_port = htons(port);
		
		int bindResult = bind(sockfd, (struct sockaddr *)&destaddr, sizeof(struct sockaddr_in));
		if(bindResult == -1) {
			//perror("Error binding the socket");
			fprintf(bt_args->logFile, "Error binding the socket\n");
			close(sockfd);
			return -1;
		}
	
		int listenResult = listen(sockfd, 5);			// 5 is the queue backlog
		if(listenResult == -1) {
			perror("Error listening on the socket");
			close(sockfd);
			return -1;
		}
	}
	return sockfd;				// success
}

int client_mode(peer_t * peer, bt_args_t * bt_args, char * handshake) {
	
	int bufferSize = sizeof(bt_msg_t) + bt_args->bt_info->piece_length;
	unsigned char * buff = malloc(bufferSize);
	//printf("Success\n");
	bt_msg_t * messageToReceive;
	int downloadedAmount = 0;
	FILE * fp;
		
	//null out the file
	fp = fopen(bt_args->save_file, "w+");
	if(fp == NULL) {
		perror("Error opening file");
		fprintf(bt_args->logFile, "Error opening file\n");
		exit(-1);
	}
	fclose(fp);
	
	//connect to the server	
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock == -1) {
		perror("Error opening socket");
		fprintf(bt_args->logFile, "Error opening socket\n");
		return -1;
	}

	int result = connect(sock, (struct sockaddr *)&(peer->sockaddr), sizeof(struct sockaddr_in));
	if(result == -1) {
		perror("Error connecting to the server");
		fprintf(bt_args->logFile, "Error connecting to the server\n");
		close(sock);
		fclose(bt_args->logFile);
		exit(0);
	}

	fprintf(bt_args->logFile, "Connection to host %s on port %d successfull.\n", inet_ntoa(peer->sockaddr.sin_addr), ntohs(peer->sockaddr.sin_port));
	
	// if verbose flag is set
	if(bt_args->verbose)
		printf("Connection to host %s on port %d successfull.\n", inet_ntoa(peer->sockaddr.sin_addr), ntohs(peer->sockaddr.sin_port));
	
	peer->socketDescriptor = sock;
	
	//send handshake
	write(sock, handshake, 68);
	fprintf(bt_args->logFile, "Handshake sent to: %s\n", peer->ip);
	if(bt_args->verbose)
		printf("Handshake sent to: %s\n", peer->ip);
	  			  
	//receive handshake
	char * handshakeToReceive = malloc(68);
	read(sock, handshakeToReceive, 68);
	fprintf(bt_args->logFile, "\nReceived handshake from: %s\n", peer->ip);
	//printf("Strlen: %zd\n", strlen(handshakeToReceive));
	if(compareHandshake(bt_args, handshakeToReceive, handshake) == 1) {
		if(bt_args->verbose)
			printf("Protocol string match successful\n");
	}
	  			  
	//printf("Now comparing IDs:\n");
	//fwrite(handshakeToReceive + 48, 20, 1, stdout);
	//printf("\n");
	//fwrite(peer->id, 20, 1, stdout);
	//printf("\n");
	//if(strncmp(handshakeToReceive + 48, (char * ) bt_args.peers[i]->id, 20) == 0)
	if(memcmp(handshakeToReceive + 48, (char * ) peer->id, 20) == 0) {
		if(bt_args->verbose)
			printf("ID match successful\n");
	}
	else {
		printf("ID match failed\n");
		fprintf(bt_args->logFile, "ID match failed\n");
		close(sock);
		free(handshakeToReceive);
		fclose(bt_args->logFile);
		exit(-1);
	}

	free(handshakeToReceive);
	
	bt_msg_t requestMessage;
	int i, j;
	for(i = 0; i < MAX_CONNECTIONS; i++){
		if(bt_args->peers[i] != NULL){
			for(j = 0; j < bt_args->bt_info->num_pieces; j++){
					requestMessage.length = htonl(sizeof(bt_msg_t) + 1);
					requestMessage.bt_type = BT_REQUEST;
					//printf("j: %d\n", j);
					requestMessage.payload.request.index = htonl(j);
					//printf("requestMessage.payload.request.index: %d\n", requestMessage.payload.request.index);
					requestMessage.payload.request.begin = htonl(0);
					requestMessage.payload.request.length = htonl(bt_args->bt_info->piece_length);
					
					//printf("Request values\n");
					//printf("requestMessage.length: %d\n", requestMessage.payload.request.length);
					//printf("requestMessage.index: %d\n", requestMessage.payload.request.index);
					//printf("requestMessage.bt_type: %d\n", requestMessage.bt_type);
					
					//write(bt_args->peers[i]->socketDescriptor, (unsigned char *) &requestMessage, sizeof(bt_msg_t));
					if(send_to_peer(bt_args, bt_args->peers[i], &requestMessage)){
						return -1;
					}
					
					//printf("Request message sent to peer: %s, piece: %d, offset: %d, length: %d\n", bt_args->peers[i]->ip, j, j*bt_args->bt_info->piece_length, bt_args->bt_info->piece_length);
					fprintf(bt_args->logFile, "Request message sent to peer: %s, piece: %d, offset: %d, length: %d\n", bt_args->peers[i]->ip, j, j*bt_args->bt_info->piece_length, bt_args->bt_info->piece_length);
					if(bt_args->verbose)
						printf("Requested %d from peer %s\n", j, bt_args->peers[i]->ip);
					
					messageToReceive = (bt_msg_t *) buff;
					//if(read(bt_args->peers[i]->socketDescriptor, messageToReceive, sizeof(buff)) < 0)
					if(read_from_peer(bt_args, bt_args->peers[i], messageToReceive) == -1) {
						perror("Read");
						free(messageToReceive);
						//return -1;
					}
					//printf("messageToReceive->bt_type: %d\n", messageToReceive->bt_type);
					//printf("messageToReceive->length: %d\n", messageToReceive->length);
					else if(ntohl(messageToReceive->length) > 0) {
						//printf("messageToReceive->bt_type: %d\n", messageToReceive->bt_type);
						switch(messageToReceive->bt_type) {
							case(BT_PIECE):
								//printf("Message received of type: %ud\n", messageToReceive->bt_type);
								if(bt_args->verbose)
									printf("Received piece from: %s\n", bt_args->peers[i]->ip);
								fprintf(bt_args->logFile, "Received piece from: %s\n", bt_args->peers[i]->ip);
								if(save_piece(bt_args, &messageToReceive->payload.piece, ntohl(messageToReceive->length) - sizeof(bt_piece_t) - sizeof(int)) == -1) {
									fprintf(bt_args->logFile, "Saving piece %d. Failed\n", messageToReceive->payload.piece.index);
									printf("Saving piece %d. Failed\n", messageToReceive->payload.piece.index);
									free(messageToReceive);
									//return -1;										
								}
								else {
									downloadedAmount += ntohl(messageToReceive->length);
									displayProgress(downloadedAmount, bt_args);
								}
								//else
									//puts("Save successful");
								break;
							
							default:
								printf("Wrong message type received\n");
						}
					}
					
					//break;
				//}
			}
			//puts("After for");
			break;
		}
	}
	//puts("After 2nd for");
	close(sock);
	peer->socketDescriptor = -1;
	peer = NULL;
	free(peer);
	free(messageToReceive);
	fclose(bt_args->logFile);
	//free(buff);
	return 0;
}

int server_mode(bt_args_t *bt_args, int listenSocket, char * originalHandshake) {
	int i;
	int connfd;
	 
	struct sockaddr_in clientAddr;
	unsigned int clientLen;
	char * handshakeToReceive;
	unsigned char * buff = malloc(sizeof(bt_msg_t) + bt_args->bt_info->piece_length);
	unsigned char * sendBuff = malloc(sizeof(bt_msg_t) + bt_args->bt_info->piece_length);
	bt_msg_t * messageToReceive;
	bt_msg_t * messageToSend;

	int maxFd = 0;
	fd_set masterSet;
	
	FD_ZERO(&masterSet);
	 			
	FD_SET(listenSocket, &masterSet);

	if(maxFd < listenSocket)
		maxFd = listenSocket;
	
 	for(;;) {
 		
 		//puts("Inside infinite for");
		if(FD_ISSET(listenSocket, &masterSet)) {
			connfd = accept(listenSocket, (struct sockaddr*)&clientAddr, &clientLen);
			if(connfd < 0) {
				//perror("accept");
				//exit(-1);
			}
			
			else {
				//printf("Inside else\n");
				printf("Peer %s:%hd added\n", inet_ntoa(clientAddr.sin_addr), clientAddr.sin_port);
				fprintf(bt_args->logFile, "Peer %s:%hd added\n", inet_ntoa(clientAddr.sin_addr), clientAddr.sin_port);	    
				//init-peer
				peer_t * peerToAdd = malloc(sizeof(peer_t));
				char peerID[20];
				init_peer(peerToAdd, peerID, inet_ntoa(clientAddr.sin_addr), clientAddr.sin_port);
				add_peer(peerToAdd, bt_args, "hostname", clientAddr.sin_port, connfd);
				//printf("Init and add success\n");

				FD_SET(peerToAdd->socketDescriptor, &masterSet);
				if (maxFd < peerToAdd->socketDescriptor)
					maxFd = peerToAdd->socketDescriptor;

				
				handshakeToReceive = malloc(68);
				// read handshake from client
				read(connfd, handshakeToReceive, 68);
				fprintf(bt_args->logFile, "Received handshake from: %s\n", peerToAdd->ip);
				if(compareHandshake(bt_args, handshakeToReceive, originalHandshake) == 1) {
					fprintf(bt_args->logFile, "Handshake match successful\n");
					if(bt_args->verbose)
						fprintf(stdout, "Handshake match successful\n");
				}
				// send handshake to client
				write(connfd, originalHandshake, 68);
				fprintf(bt_args->logFile, "Handshake sent to: %s\n", peerToAdd->ip);
				free(handshakeToReceive);
				//free(peerToAdd);
			}
		}

		for(i = 0; i < MAX_CONNECTIONS; i++) {

			//for(;;) {
				//poll through clients
				//for(i = 0; i < MAX_CONNECTIONS; i++) {
					//printf("Inside poll for\n");
					if(bt_args->peers[i] != NULL && FD_ISSET(bt_args->peers[i]->socketDescriptor, &masterSet)) {
						messageToReceive = (bt_msg_t *) buff;
						messageToSend = (bt_msg_t *) sendBuff;
						//if(read(bt_args->peers[i]->socketDescriptor, messageToReceive, sizeof(buff)) < 0) {
						//	perror("Read");
						//	return -1;
						//}
						if(read_from_peer(bt_args, bt_args->peers[i], messageToReceive) == -1) {
							perror("Read");
							drop_peer(bt_args->peers[i], bt_args);
							free(messageToReceive);
							free(messageToSend);
							//fclose(bt_args->logFile);
							break;
							//return -1;
						}
						//printf("messageToReceive->length: %d\n", messageToReceive->length);
						else if(ntohl(messageToReceive->length > 0)) {
							switch(messageToReceive->bt_type) {					
								case(BT_REQUEST):
									//fprintf(bt_args->logFile, "Message received of type: %ud\n", messageToReceive->bt_type);
									fprintf(bt_args->logFile, "Message request from peer: %s piece: %d\n", bt_args->peers[i]->ip, ntohl(messageToReceive->payload.request.index));
									if(bt_args->verbose)
										//printf("Request for %d from %s\n", ntohl(recv->payload.request.index), current->straddr);
										printf("Request for piece %d from peer: %s\n", ntohl(messageToReceive->payload.request.index), bt_args->peers[i]->ip);
									//if(we_have(bt_args, ntohl(recv->payload.request.index))){
									//messageToSend.length = sizeof(bt_msg_t) + 1;
									messageToSend->bt_type = BT_PIECE;
									messageToSend->payload.piece.index = messageToReceive->payload.request.index;
									messageToSend->payload.piece.begin = htonl(0);
									//printf("messageToSend values\n");
									//printf("messageToSend.index: %d\n", messageToSend.payload.piece.index);
									//printf("messageToSend.begin: %d\n", messageToSend.payload.piece.begin);
									messageToSend->length = htonl(sizeof(bt_piece_t) + load_piece(bt_args, &messageToSend->payload.piece) + 1 + 3);
									//printf("messageToSend.length: %d\n", messageToSend->length);
									//printf("After load\n");
									if(send_to_peer(bt_args, bt_args->peers[i], messageToSend) == -1){
										drop_peer(bt_args->peers[i], bt_args);
										//bt_args->peers[i]->socketDescriptor = -1;
										//bt_args->peers[i] = NULL;
										free(bt_args->peers[i]);
										free(messageToReceive);
										free(messageToSend);
										//fclose(bt_args->logFile);
										//return 1;
									}
									
									//write(bt_args->peers[i]->socketDescriptor, (unsigned char *) &messageToSend, sizeof(bt_msg_t));
									fprintf(bt_args->logFile, "Response for BT_REQUEST sent to peer: %s\n", bt_args->peers[i]->ip);
									if(bt_args->verbose)
										fprintf(stdout, "Response for BT_REQUEST sent to peer: %s\n", bt_args->peers[i]->ip);
									//}
									//bt_args->peers[i]->socketDescriptor = -1;
									//bt_args->peers[i] = NULL;
									//free(bt_args->peers[i]);
									break;
								
								default:
									printf("Wrong message received\n");
									printf("Message received of type: %ud\n", messageToReceive->bt_type);
									free(messageToReceive);
									free(messageToSend);
									//exit(-1);
								}
							memset(messageToReceive, 0, sizeof(messageToReceive));
							memset(messageToSend, 0, sizeof(messageToSend));
							}
						}
					}
			//}
		//}
	}
 	
 	free(messageToReceive);
 	free(messageToSend);
	
	return 0;
}

int save_piece(bt_args_t *bt_args, bt_piece_t *piece, int messageLength) {
	//printf("Inside save_piece\n");
	FILE * save;
	size_t amount;
	unsigned char hash[20];

	//printf("Payload from piece: %s\n", piece->piece);
  
	sha1_piece(bt_args, piece, hash, messageLength);
	//printf("Computed hash: %s\n", hash);
	//printf("piece->index: %d\n", ntohl(piece->index));
	//printf("message length: %d\n", messageLength);
	//printf("Stored hash: %s\n", bt_args->bt_info->piece_hashes[ntohl(piece->index)]);

	if(memcmp(bt_args->bt_info->piece_hashes[ntohl(piece->index)], hash, 20)){
		printf("Received piece %d has bad hash\n", ntohl(piece->index));
		return -1;
	}

	if((save = fopen(bt_args->save_file, "a")) == NULL){
		perror("Cannot open file");
		return -1;
	}
  
	if(fseek(save, ntohl(piece->index) * bt_args->bt_info->piece_length + ntohl(piece->begin), SEEK_SET) < 0){
		perror("Fseek error");
		return -1;
	}
	amount = 0;

	//fwrite(piece->piece, 1, messageLength ,save);
	while((amount += fwrite(piece->piece + amount, 1, messageLength - amount, save)) < messageLength);
	fclose(save);

	fprintf(bt_args->logFile, "Piece %d saved successfully\n", ntohl(piece->index));
	printf("Piece %d saved successfully\n", ntohl(piece->index));

	return 0;
}

int load_piece(bt_args_t *bt_args, bt_piece_t *piece) {
	
	//printf("Piece values\n");
	//printf("Piece->index: %d\n", ntohl(piece->index));
	//printf("Piece length: %d\n", bt_args->bt_info->piece_length);
	//printf("Piece->begin: %d\n", ntohl(piece->begin));
	  
	FILE * loadFile;
	size_t currentSize, finalSize, totalSize;
	
	currentSize = 0;
	finalSize = 0;
	totalSize = bt_args->bt_info->piece_length - ntohl(piece->begin);
	printf("Total size: %zd\n", totalSize);

	//printf("Save file name: %s\n", bt_args->save_file);
	if((loadFile = fopen(bt_args->save_file, "r")) == NULL){
		perror("Error opening file");
		return -1;
	}
  
	fprintf(bt_args->logFile, "File open success\n");

	//printf("big value: %d\n", ntohl(piece->index) * bt_args->bt_info->piece_length + ntohl(piece->begin));
  
	if(fseek(loadFile, ntohl(piece->index) * bt_args->bt_info->piece_length + ntohl(piece->begin), SEEK_SET) < 0){
		perror("Fseek error");
		return -1;
	}
	fprintf(bt_args->logFile, "Fseek success\n");
	//piece->piece = malloc(sizeof(total));
  
	//fread(piece->piece, 1, total, load);

	//printf("Amount: %zd", amount);
	//printf("Total: %zd", total);
	while((currentSize += fread(piece->piece + currentSize, 1, totalSize - currentSize, loadFile)) < totalSize) {
		//printf("Inside while\n");
		if(currentSize == finalSize) {
			break;
		}
		
		finalSize = currentSize;
	}
	fclose(loadFile);
	//printf("Loaded data: %s\n", (char *) piece->piece);
	fprintf(bt_args->logFile, "Load completed. Closing file.\n");

	fprintf(bt_args->logFile, "Loaded %d\n", ntohl(piece->index));
	return currentSize;
}

int send_to_peer(bt_args_t * bt_args, peer_t * peer, bt_msg_t * msg)
{
	int currentSize, totalSize;
	int maxSize = 1000;
	int sizeToSend;
	int finalSize;

	unsigned char * buff = (unsigned char *) msg;
	currentSize = 0;
	finalSize = 0;

	if(peer->socketDescriptor == -1){
		printf("Peer disconnected: %s\n", peer->ip);
		fprintf(bt_args->logFile, "Peer disconnected: %s\n", peer->ip);
		return -1;
	}

	totalSize = ntohl(msg->length) + sizeof(int);

	while(currentSize < totalSize) {
		//sleep(2);
		if (totalSize - currentSize < maxSize)
			sizeToSend = totalSize - currentSize;
		else
			sizeToSend = maxSize;
    
		//printf("Sendbuf: %s", sendbuf + amount);
		//fprintf(stdout, "Sendbuf: %s", sendbuf + amount);
		if((currentSize += write(peer->socketDescriptor, buff + currentSize, sizeToSend)) < 0) {
			printf("Peer disconnected: %s\n", peer->ip);
			fprintf(bt_args->logFile, "Peer disconnected: %s\n", peer->ip);
			return -1;
		}
    
		if(finalSize >= currentSize) {
			fprintf(bt_args->logFile, "Peer disconnected: %s\n", peer->ip);
			printf("Peer disconnected: %s\n", peer->ip);
			return -1;
		}
    
		//printf("Written\n");
		finalSize = currentSize;
	}
  
	fprintf(bt_args->logFile, "Sent message of length %d to peer: %s\n", totalSize, peer->ip);
	fprintf(stdout, "Sent message of length %d to peer: %s\n", totalSize, peer->ip);
	return 0;
}

int read_from_peer(bt_args_t * bt_args, peer_t * peer, bt_msg_t * msg)
{
	//puts("Read from peer");
	unsigned char * buff;
	int currentSize, messageLength;
	int finalSize;
	buff = (unsigned char *) msg;
	int readLength;
	//buff = malloc(sizeof(bt_msg_t));
  
	currentSize = 0;
	finalSize = -1;
	if(peer->socketDescriptor == -1) {
		printf("Peer disconnected: %s\n", peer->ip);
		fprintf(bt_args->logFile, "Peer disconnected: %s\n", peer->ip);
		return -1;
	}

	readLength = read(peer->socketDescriptor, buff, sizeof(int));
	if(readLength < 0) {
		perror("read");
		printf("Peer disconnected: %s\n", peer->ip);
		fprintf(bt_args->logFile, "Peer disconnected: %s\n", peer->ip);
		return -1;
	}

	//printf("msg->length: %d\n", msg->length);
	messageLength = ntohl(msg->length);
	buff += sizeof(int);

	if(messageLength > 0)
		fprintf(bt_args->logFile, "Reading from peer: %s Message Length: %d\n", peer->ip, messageLength);
	while(currentSize < messageLength){
		//sleep(2);
		//printf("Inside while\n");
		//printf("Amount: %d\n", currentSize);
		//printf("msglen: %d\n", messageLength);
		currentSize += read(peer->socketDescriptor, buff + currentSize, messageLength - currentSize);
		if(currentSize < 0) {
			printf("Peer disconnected: %s\n", peer->ip);
			fprintf(bt_args->logFile, "Peer disconnected: %s\n", peer->ip);
			return -1;
		}
	
		if(finalSize >= currentSize) {
			fprintf(bt_args->logFile, "Peer disconnected: %s\n", peer->ip);
			printf("Peer disconnected: %s\n", peer->ip);
			//peer->socketDescriptor = -1;
			//peer = NULL;
			return -1;
		}
		
		finalSize = currentSize;
		//printf("msg->bt_type: %d\n", msg->bt_type);
		//printf("Buf: %s\n", buff);
	}
	
	if(messageLength > 0)
  	  	fprintf(bt_args->logFile, "Read %d bytes from peer: %s\n", messageLength, peer->ip);

	//printf("Buf: %s\n", (unsigned char *) buff);
	//msg = (bt_msg_t *) buff;

	//printf("piece data: %s\n", msg->payload.piece.piece);
	//printf("Sizeof msg: %zd\n", sizeof(msg));
	//printf("Sizeof buff: %zd\n", sizeof(buff));
  
	return messageLength; //amount;
}

int sha1_piece(bt_args_t * bt_args, bt_piece_t * piece, unsigned char * hash, int messageLength) {
	int i;
	//int len = ntohl(piece->length) - sizeof(bt_piece_t) - 4;
	//printf("Data to be hashed: %s\n", (unsigned char *)piece->piece);
	SHA1((unsigned char *)piece->piece, messageLength, hash);
	if(bt_args->verbose) {
		printf("Hashing piece %d\n", ntohl(piece->index));
		for(i = 0; i < 20; i++) {
			printf("\%02x", hash[i]);
		}
		printf("\n");
	}
	return 0;
}

int add_peer(peer_t *peer, bt_args_t *bt_args, char * hostname, unsigned short port, int socketDescriptor) {
	int i;
	for(i = 0; i < MAX_CONNECTIONS; i++){
		if(bt_args->peers[i] == NULL){
			bt_args->peers[i] = peer;
			bt_args->peers[i]->socketDescriptor = socketDescriptor;
			if(bt_args->verbose)
				printf("Peer %s:%hd added\n", inet_ntoa(peer->sockaddr.sin_addr), peer->sockaddr.sin_port);
	        	//int clientSocket = client_mode();
				return 0;
	        }
	    }
	return -1;
}

int drop_peer(peer_t *peer, bt_args_t *bt_args)
{
    int i;
    for(i = 0; i < MAX_CONNECTIONS; i++){
      if(bt_args->peers[i] == peer){
          printf("Peer dropped\n");
          printf("IP: %s\n", peer->ip);
          free(bt_args->peers[i]);
          if(bt_args->verbose)
        	  printf("Peer %s:%hd dropped\n", peer->ip, peer->port);
          fprintf(bt_args->logFile, "Peer %s:%hd dropped\n", peer->ip, peer->port);
          bt_args->peers[i] = NULL;
          return 0;
      }
    }
    return -1;
}

char * generateHandshake(bt_args_t *bt_args) {
	// referenced from https://github.com/kristenwidman/Bittorrenter/blob/master/messages.py
	char * hashGen = (char *) malloc(68);
	bzero(hashGen, 68);
	
	memcpy(hashGen, "\23BitTorrent Protocol", 20);
	memcpy(hashGen + 20, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
	memcpy(hashGen + 28, bt_args->bt_info->info_hash, 20);
	memcpy(hashGen + 48, bt_args->id, 20);
	
	return hashGen;
}

int compareHandshake(bt_args_t * bt_args, char * received, char * original) {
	fprintf(bt_args->logFile, "Received handshake: %s\n", received);
	//printf("Strlen: %zd\n", strlen(received));
	fprintf(bt_args->logFile, "Original handshake: %s\n", original);
	//printf("Strlen: %zd\n", strlen(original));
	//printf("Now comparing:\n");
	//fwrite(received, 28, 1, stdout);
	//printf("\n");
	//fwrite(original, 28, 1, stdout);
	//printf("\n");
	if(strncmp(received, original, 28) != 0) {
	//if(memcmp(received, original, 28) != 0) {
		printf("Received incorrect bittorrent string\n");
		fprintf(bt_args->logFile, "Received incorrect bittorrent string\n");
		return -1;
	}
	
	else {
		//printf("Received correct bittorrent string\n");
		fprintf(bt_args->logFile, "Received correct bittorrent string\n");
	}
	
	//printf("Now comparing:\n");
	//fwrite(received + 28, 20, 1, stdout);
	//printf("\n");
	//fwrite(original + 28, 20, 1, stdout);
	//printf("\n");
	if(strncmp(received + 28, original + 28, 20) != 0) {
	//if(memcmp(received + 28, original + 28, 20) != 0) {
		printf("Received incorrect info hash\n");
		fprintf(bt_args->logFile, "Received incorrect info hash\n");
		return -1;
	}
	
	else
		//printf("Received correct info hash\n");
		fprintf(bt_args->logFile, "Received correct info hash\n");
		
	
	return 1;
}

void displayProgress(int messageLength, bt_args_t * bt_args) {
	int i;
	float downloadPercent;
	int downloadedInKB = messageLength / 1024;
	int peerCounter = 0;
	
	for(i = 0; i < MAX_CONNECTIONS; i++) {
		if(bt_args->peers[i] != NULL)
			peerCounter++;
	}
	
	//printf("Messagelength: %d\n", messageLength);
	//printf("Length: %d\n", bt_args->bt_info->length);
	downloadPercent = (float)messageLength / bt_args->bt_info->length * 100;
	//printf("%d", bt_args->bt_info->length);
	printf("File: %s Progress: %.2f%% Peers: %d Downloaded: %d KB\n", bt_args->save_file, peerCounter, downloadPercent, downloadedInKB);	
}