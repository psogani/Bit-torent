#ifndef _BT_LIB_H
#define _BT_LIB_H

//standard stuff
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <poll.h>

//networking stuff
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#include "bt_lib.h"
#include "bencode.h"


/*Maximum file name size, to make things easy*/
#define FILE_NAME_MAX 1024

/*Maxium number of connections*/
#define MAX_CONNECTIONS 5

/*initial port to try and open a listen socket on*/
#define INIT_PORT 6667 

/*max port to try and open a listen socket on*/
#define MAX_PORT 6699

/*Different BitTorrent Message Types*/
#define BT_CHOKE 0
#define BT_UNCHOKE 1
#define BT_INTERSTED 2
#define BT_NOT_INTERESTED 3
#define BT_HAVE 4
#define BT_BITFIELD 5
#define BT_REQUEST 6
#define BT_PIECE 7
#define BT_CANCEL 8

/*size (in bytes) of id field for peers*/
#define ID_SIZE 20


//holds information about a peer
typedef struct peer{
  unsigned char id[ID_SIZE]; //the peer id
  unsigned short port; //the port to connect n
  struct sockaddr_in sockaddr; //sockaddr for peer
  int socketDescriptor;
  char ip[INET_ADDRSTRLEN];
  int bitfield; //bitfield received?
  int choked; //peer choked?
  int interested; //peer interested?
}peer_t;


//holds information about a torrent file
typedef struct {
  char announce[FILE_NAME_MAX]; //url of tracker
  char name[FILE_NAME_MAX]; //name of file
  int piece_length; //number of bytes in each piece
  int length; //length of the file in bytes
  int num_pieces; //number of pieces, computed based on above two values
  char ** piece_hashes; //pointer to 20 byte data buffers containing the sha1sum of each of the pieces
  unsigned char * info_hash; //SHA1 of bencoded info value
} bt_info_t;

typedef struct {
	size_t size;//size of the bitfiled
	unsigned char * bitfield; //bitfield where each bit represents a piece that
                   //the peer has or doesn't have
} bt_bitfield_t;

//holds all the agurments and state for a running the bt client
typedef struct {
  int verbose; //verbose level
  char save_file[FILE_NAME_MAX];//the filename to save to
  FILE * f_save;
  FILE * logFile;
  char log_file[FILE_NAME_MAX];//the log file
  char torrent_file[FILE_NAME_MAX];// *.torrent file
  peer_t * peers[MAX_CONNECTIONS]; // array of peer_t pointers
  //unsigned int id; //this bt_clients id
  unsigned char id[ID_SIZE]; //this bt_clients id
  int sockets[MAX_CONNECTIONS]; //Array of possible sockets
  struct pollfd poll_sockets[MAX_CONNECTIONS]; //Arry of pollfd for polling for input
  char ipAddr[INET_ADDRSTRLEN];
  int ipFlag;
  unsigned short port;
  int pFlag;
  int saveFileFlag;
  
  /*set once torrent is parse*/
  bt_info_t * bt_info; //the parsed info for this torrent
  bt_bitfield_t * peerBitfields[MAX_CONNECTIONS];
  bt_bitfield_t bitfield;

} bt_args_t;


/**
 * Message structures
 **/

typedef struct{
  int index; //which piece index
  int begin; //offset within piece
  int length; //amount wanted, within a power of two
} bt_request_t;

typedef struct{
  int index; //which piece index
  int begin; //offset within piece
  unsigned char piece[0]; //pointer to start of the data for a piece
} bt_piece_t;



typedef struct bt_msg{
  int length; //length of remaining message, 
              //0 length message is a keep-alive message
  unsigned int bt_type;//type of bt_mesage

  //payload can be any of these
  union { 
    bt_bitfield_t bitfield;//send a bitfield
    int have; //what piece you have
    bt_piece_t piece; //a peice message
    bt_request_t request; //request messge
    bt_request_t cancel; //cancel message, same type as request
    char data[0];//pointer to start of payload, just incase
  }payload;

} bt_msg_t;





int parse_bt_info(bt_args_t * bt_args, bt_info_t * bt_info, be_node * node, char *keyToCompare);

/*choose a random id for this node*/
unsigned int select_id();

/*propogate a peer_t struct and add it to the bt_args structure*/
int add_peer(peer_t *peer, bt_args_t *bt_args, char * hostname, unsigned short port, int socketDescriptor);

/*drop an unresponsive or failed peer from the bt_args*/
int drop_peer(peer_t *peer, bt_args_t *bt_args);

/* initialize connection with peers */
int init_peer(peer_t *peer, char * id, char * ip, unsigned short port);


/*calc the peer id based on the string representation of the ip and
  port*/
void calc_id(char * ip, unsigned short port, char * id);

/* print info about this peer */
void print_peer(peer_t *peer);

/* check status on peers, maybe they went offline? */
int check_peer(peer_t *peer);

/*check if peers want to send me something*/
int server_mode(bt_args_t *bt_args, int listenSocket, char * originalHandshake);

/*send a msg to a peer*/
int send_to_peer(bt_args_t * bt_args, peer_t * peer, bt_msg_t * bt_msg);

/*read a msg from a peer and store it in msg*/
int read_from_peer(bt_args_t * bt_args, peer_t * peer, bt_msg_t * bt_msg);


/* save a piece of the file */
int save_piece(bt_args_t * bt_args, bt_piece_t * piece, int messageLength);

/*load a piece of the file into piece */
int load_piece(bt_args_t * bt_args, bt_piece_t * piece);

/*load the bitfield into bitfield*/
int get_bitfield(bt_args_t * bt_args, bt_bitfield_t * bitfield);

/*compute the sha1sum for a piece, store result in hash*/
int sha1_piece(bt_args_t * bt_args, bt_piece_t * piece, unsigned char * hash, int messageLength);

/*Contact the tracker and update bt_args with info learned, 
  such as peer list*/
int contact_tracker(bt_args_t * bt_args);

// server mode
int listen_mode(bt_args_t * bt_args, unsigned short port, char * ipv4, int ipFlag);

// client mode
int client_mode(peer_t * peer, bt_args_t * bt_args, char * handshake);

char * generateHandshake(bt_args_t *bt_args);

int compareHandshake(bt_args_t * bt_args, char * received, char * original);

void displayProgress(int messageLength, bt_args_t * bt_args);

#endif
