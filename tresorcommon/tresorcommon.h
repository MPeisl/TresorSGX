#ifndef TRESORCOMMON_H
#define TRESORCOMMON_H

#ifdef __KERNEL__
#include <linux/netlink.h>
#endif //__KERNEL__

#ifdef TRESOR_DAEMON
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#endif //TRESOR_DAEMON

/* ******************************
 *      DIRECTORIES
 * ****************************** */

char *enclavefilepath = "/usr/src/workdir/tresorencl/Enclave/tresorencl.so"; // TODO modify me
char *sealfilepath = "/usr/src/workdir/seals/sealedBlob.txt";  // TODO modify me
char *setkey_pipename = "/tmp/tresorsgxsetkey";

#define usermodehelper_daemon "/opt/tresorsgx/tresord"
#define usermodehelper_home "HOME=/usr/bin"


/* ******************************
 *      Tresor COMMON
 * ****************************** */

#define DEBUG_ENCLAVE       (1) // starts SGX enclave in debugmode if set
#define SEALED_CRYPTO       (1) // enables usage of sealed salt
#define SETKEY_BYPIPE       (0) // daemon opens a pipe for key setting
#define STARTDAEMON_BY_LKM  (0) // the daemon is started using the usermode on lkm launch

#define SEAL_MAX_BLOB_SIZE  1024 // sealed blob maximum size

/* Tresor Error codes */
/* Dont use 0x[0-5]00[0-F] because they are used by SGX*/ 
enum {
    TRESOR_OK =                     0x0000,
    TRESOR_FAIL =                   0x0001, // generic error
    TRESOR_SEALBUF_TOO_SMALL =      0x0010, // in enclave seal buffer to small for sealed object
    TRESOR_BLOB_INVALID =           0x0020, // in enclave blob did not decrypt or was truncated
    TRESOR_SGX_RAND_FAILURE =       0x0030, // in enclave sgx_read_rand failed
    TRESOR_SGX_SEAL_FAILURE =       0x0040, // in enclave sgx_seal_data failed
    TRESOR_SEALFILE_NOTAVAILABLE =  0x0050, // sealfile cant be loaded
    TRESOR_SEALFILE_WRITEFAIL =     0x0060, // error during sealfile write
    TRESOR_DAEMON_EXIT =            0x0070, // exit daemon netlink receive loop
    TRESOR_NL_NODAEMON_REGISTERED = 0x0080, // no daemon registered at lkm, dont now whom to send msg
    TRESOR_NL_FAILED_MSG_CREATION = 0x0090, // genlmsg creation failed
    TRESOR_NL_FAILED_UNICAST =      0x00A0, // unicast went wrong
    TRESOR_NL_IS_NULL =             0x00B0, // Netlink info is null
};


enum aes_algorithm {
    AES_128_BLK,
    AES_192_BLK,   
    AES_256_BLK,   
    AES_128_CTR,   // not used but supported by sgx crypto
    AES_192_CTR,   // not used but supported by sgx crypto
    AES_256_CTR,   // not used but supported by sgx crypto
    AES_128_CBC,   // not used but supported by sgx crypto
    AES_192_CBC,   // not used but supported by sgx crypto
    AES_256_CBC    // not used but supported by sgx crypto
};


/* ******************************
 *      NETLINK COMMON
 * ****************************** */

#define TRESOR_NL_FAMILY_NAME "TRESOR_NETLINK"
#define TRESOR_NL_VERSION 2
/*version 2 due to policy changes*/
#define MAX_DATA_LEN 64

// used as function param
struct tresor_nl_msg {
    uint32_t operation;
    uint32_t data_len;
    char data[MAX_DATA_LEN];
};

// Netlink policy attributes
enum {
    TRESOR_NL_A_UNSPEC,
    TRESOR_NL_A_OP, // uint32_t
    TRESOR_NL_A_DATA_LEN, // uint32_t
    TRESOR_NL_A_DATA, // nul-terminated string!
    __TRESOR_NL_A_MAX,
};

#define TRESOR_NL_A_MAX (__TRESOR_NL_A_MAX - 1)

// Netlink operations
enum {
    TRESOR_NL_O_UNSPEC,
    TRESOR_NL_O_CMD,
    __TRESOR_NL_O_MAX,
};

#define TRESOR_NL_O_MAX (__TRESOR_NL_O_MAX - 1)
 
// Netlink Message operation types
enum {
    TRESOR_MSG_EXITDAEMON,
    TRESOR_MSG_REGISTER,
    TRESOR_MSG_SAVEKEY,
    TRESOR_MSG_ENCRYPT,
    TRESOR_MSG_DECRYPT
};

//Generic-Netlink policy
#if defined(__KERNEL__) || defined(TRESOR_DAEMON)
static struct nla_policy tresor_genl_policy[TRESOR_NL_A_MAX + 1] = {
    [TRESOR_NL_A_OP] = {
        .type = NLA_U32,
    },
    [TRESOR_NL_A_DATA_LEN] = {
        .type = NLA_U32,
    },
    [TRESOR_NL_A_DATA] = {
        .type = NLA_NUL_STRING,
        #ifdef __KERNEL__
        .len = MAX_DATA_LEN,
        #else
        .maxlen = MAX_DATA_LEN,
        #endif //__KERNEL__
    }
};
#endif //(__KERNEL__ || TRESOR_DAEMON)
#endif //TRESORCOMMON_H