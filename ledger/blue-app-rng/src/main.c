// Copyright (C) 2017 Oraclize LTD

#include "os.h"

#include "os_io_seproxyhal.h"


#define CLA 0x80

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

ux_state_t ux;

uint64_t ticks;

#define ROLE_PUBKEY_SIGNER 0x01
#define ROLE_STATE_EXPORT_IMPORT 0x02
#define SW_CONDITIONS_NOT_SATISFIED 0x6985
#define SW_INVALID_DATA 0x6A80

#define  SN 400 //number of sectors available
#define UNUSED_SPACE (64 - 2*sizeof(uint64_t)) //sector size 64bytes - inonce - nonce

typedef struct isector_t {
    uint64_t nonce;
    char unused[UNUSED_SPACE];
} isector_t;

typedef struct nvm_sector_t {
    uint64_t write_cnt;
    isector_t isector;

} nvm_sector_t;

typedef struct sector_w1l_t {
    nvm_sector_t sector[SN];

} sector_w1l_t;


/***************** Variables stored in FLASH memory *****************/

//Must have a N_ prefix -> non volatile memory
typedef struct initialized_t {

    uint8_t initialized;

} initialized_t;                     


WIDE initialized_t N_initialized_real; 

#define N_initialized (*(WIDE initialized_t *)PIC(&N_initialized_real))

//const uint8_t N_initialized;

const cx_ecfp_private_key_t N_privateKey; 
//const cx_ecfp_public_key_t N_publicKey;


WIDE sector_w1l_t N_nvm_sector_real;

#define N_nvm_sector (*(WIDE sector_w1l_t *)PIC(&N_nvm_sector_real))


/*************************************************************/

int read_offset(sector_w1l_t *nvm_sector){

    //return the sector id -> the one to be accessed, works in a round robin fashion and wraps around after accessing sector #SN

    int i = -1;

    for(i = 0; i < SN-1; i++ ){
        //if the curent sector (i) has been written more times than the next one return its id
        if (nvm_sector->sector[i+1].write_cnt <= nvm_sector->sector[i].write_cnt){
            return i;
        }

    }

    return i;
}


uint64_t read_write_cnt(sector_w1l_t *nvm_sector,unsigned int index){

    
        return nvm_sector->sector[index].write_cnt;
        

}

nvm_sector_t * read_address(sector_w1l_t *nvm_sector,unsigned int index){

    return &nvm_sector->sector[index];

}

isector_t read(sector_w1l_t *nvm_sector){

    //return the sector data (isector) corresponing to the sector id  obtained by read_offset()
    int sector_id;

    BEGIN_TRY {
            TRY {
                sector_id = read_offset(nvm_sector);
                if (sector_id == -1)
                    THROW(0x6D00);
            }
        CATCH_OTHER(e) {
        }
        FINALLY {
        }
    }
    END_TRY;

    return nvm_sector->sector[sector_id].isector;

}


void write(sector_w1l_t *nvm_sector, isector_t isector){

    //copy the data to be stored (isector) and update the sector write counter (previous sector write cnt+1)
    nvm_sector_t nvm_sector_temp;

    int sector_id;

    BEGIN_TRY {
            TRY {
                //get the lastly written sector id
                sector_id = read_offset(nvm_sector);

                if (sector_id == -1)
                    THROW(0x6D00);

                //increase the write cnt (of the last modified sector) by 1 and store it in the next sector
                nvm_sector_temp.write_cnt = nvm_sector->sector[sector_id].write_cnt + 1;
                //copy the data to be stored in the temp sector
                nvm_sector_temp.isector = isector;

                //copy the temp sector to the actual one, mod for wrapping arround
                nvm_write(&N_nvm_sector.sector[(sector_id+1)%SN], &nvm_sector_temp, sizeof(nvm_sector_temp));
            }
        CATCH_OTHER(e) {
        }
        FINALLY {
        }
    }
    END_TRY;
        
}

void ticks_increase(){
    //increase the ticks every time the SEPROXYHAL_TAG_TICKER_EVENT event is triggered (100ms)
    ticks++;

    return;
}

uint64_t get_state(){

    /* update state nonce and return the value*/
    isector_t isector;
    uint64_t nonce;

    //use the wear levelling mechanism
    isector = read(&N_nvm_sector); 
    nonce = isector.nonce;
    nonce++;
    isector.nonce = nonce;
    write(&N_nvm_sector, isector); //use the wear leveling write mechanism
    
    return nonce;
}

const bagl_element_t ui_idle_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "RNG",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_idle_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter);


void ui_idle(void) {
    UX_DISPLAY(ui_idle_nanos, NULL);
}


unsigned int ui_idle_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_LEFT: // EXIT
        // Go back to the dashboard
        os_sched_exit(0);
        break;
    }
    return 0;
}


unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}


void rng_main(void) {
    //rx = number of bytes received (written to the buffer by the host)
    volatile unsigned int rx = 0;
    //tx = number of bytes to be transmitted back to the host
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;
    
    volatile unsigned int n = 0;

    volatile unsigned int index;
    volatile isector_t isector,isector_dummy;
    volatile uint8_t role;

    volatile cx_ecfp_public_key_t publicKey;


    volatile uint8_t oldNode[32*16];

    volatile uint8_t hash[32];
    volatile cx_sha256_t sha;
    volatile uint64_t state_timestamp;
    
    //initial roothash of the empty tree (all leaf nodes contain the ZeroHash value
    volatile uint8_t state_roothash[] = {245, 67, 142, 13, 153, 224, 250, 125, 4, 135, 7, 178, 193, 105, 9, 178, 76, 135, 223, 155, 181, 216, 171, 245, 238, 96, 116, 202, 154, 37, 25, 26}; //f5438e0d99e0fa7d048707b2c16909b24c87df9bb5d8abf5ee6074ca9a25191a
    volatile uint64_t state_nonce;

    volatile uint64_t last_imported_state_nonce = 0;

    volatile uint8_t roothash[] = {245, 67, 142, 13, 153, 224, 250, 125, 4, 135, 7, 178, 193, 105, 9, 178, 76, 135, 223, 155, 181, 216, 171, 245, 238, 96, 116, 202, 154, 37, 25, 26}; //f5438e0d99e0fa7d048707b2c16909b24c87df9bb5d8abf5ee6074ca9a25191a

    volatile uint8_t signatureLength;
    volatile cx_ecfp_public_key_t tmpPublic;



    volatile uint8_t QI_depth;
    volatile uint8_t QI_keyhash[32];
    volatile uint8_t QI_valuehash[32];
    volatile uint8_t QI_newhash[32];
    volatile uint8_t QI_oldhash[32];
    volatile uint8_t QI_nodeOffset;
    volatile uint8_t QI_new_oldhash[32];
    volatile uint8_t QI_nexthash[32];
    volatile uint64_t QI_value_t0;
    volatile uint64_t QI_value_dt;
    volatile uint8_t QI_value_rnonce[32];
    volatile uint8_t QI_value_nbytes;

    volatile uint8_t EX_keyhash[32];
    volatile uint8_t EX_valuehash[32];
    volatile uint64_t EX_value_t0;
    volatile uint64_t EX_value_dt;
    volatile uint64_t EX_value_t1;
    volatile uint8_t EX_value_rnonce[32];
    volatile uint8_t EX_value_nbytes;
    volatile uint8_t EX_signature[80];
    volatile uint8_t EX_tosign[32+8+32+1];
    
    //ZeroHash -> sha256(32*\x00)
    volatile uint8_t QI_ZH[] = {102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37};


    //initiallize tick counter, gets updated automatically by an event trigger tha call the ticks_increase() function
    ticks = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(0x6982);
                }

                if (G_io_apdu_buffer[0] != CLA) {
                    THROW(0x6E00);
                }

                switch (G_io_apdu_buffer[1]) {

                case 0x00: // echo
                    tx = rx;
                    THROW(0x9000);
                    break;
                case 0x01: // get code hash
                    os_endorsement_get_code_hash(G_io_apdu_buffer);
                    tx = 32;
                    THROW(0x9000);
                    break;
                case 0x02: // get APPKEY1 pubkey + cert
                    os_endorsement_get_public_key(1, G_io_apdu_buffer);
                    os_endorsement_get_public_key_certificate(
                       1, G_io_apdu_buffer + 65);
                    tx = 65 + G_io_apdu_buffer[66] + 2;
                    THROW(0x9000);
                    break;
                case 0x11:
                    //get SESSIONKEY pubkey and sign it with APPKEY1

                    role = ROLE_PUBKEY_SIGNER;

                    //get the session public key from the private key stored in flash memory
                    cx_ecfp_generate_pair(CX_CURVE_256K1, &publicKey, &N_privateKey, 1);

                    os_memmove(G_io_apdu_buffer, publicKey.W, 65);
                    G_io_apdu_buffer[100] = role;
                    os_memmove(G_io_apdu_buffer + 101, publicKey.W, 65);

                    os_endorsement_key1_sign_data(G_io_apdu_buffer + 100, 66,
                                  G_io_apdu_buffer + 65);

                    tx = 65 + G_io_apdu_buffer[66] + 2;
                    THROW(0x9000);

                    break;
                case 0x12:
                    //EXPORT STATE TO HOST APP
                    isector = read(&N_nvm_sector); 
                    if (isector.nonce > last_imported_state_nonce){ //it was already exported OR you didn't import the prevstate yet since app restart
                        tx = 0;
                        THROW(0x6D00);
                        break;
                    }
                    state_nonce = get_state();

                    role = ROLE_STATE_EXPORT_IMPORT;

                    cx_sha256_init(&sha);
                    cx_hash(&sha.header, 0, &role, 1, NULL); //initialize with the role byte

                    //add the state_nonce to the data to be hashed
                    cx_hash(&sha.header, 0, &state_nonce , sizeof(state_nonce), NULL);


                    //get the current time, add it to data to be hashed 
                    state_timestamp = ticks;
                    cx_hash(&sha.header, 0, &state_timestamp, sizeof(state_timestamp), NULL);

                    //get the state_roothash add it to data to be hashed and hash them all (role_byte,state_nonce,timestamp,roothash)
                    os_memmove(&state_roothash, &roothash, sizeof(roothash));
                    cx_hash(&sha.header, CX_LAST, &state_roothash, sizeof(state_roothash), hash);


                    // copy state_nonce timestamp and state roothash to buffer
                    os_memmove(G_io_apdu_buffer, &state_nonce, sizeof(state_nonce));
                    tx = sizeof(state_nonce);

                    os_memmove(G_io_apdu_buffer + tx, &state_timestamp, sizeof(state_timestamp));
                    tx += sizeof(state_timestamp);

                    os_memmove(G_io_apdu_buffer + tx, &state_roothash, sizeof(state_roothash));
                    tx += sizeof(state_roothash);


                    // sign with the session private key and store the signature in postion tx
                    cx_ecdsa_sign(&N_privateKey, CX_LAST | CX_RND_RFC6979,
                      CX_SHA256, hash , 32, G_io_apdu_buffer + tx);

                    //first byte of the signature is 0x30, the secong one represents the length of the sig  and return them allong with  state_nonce timestamp and state_hash
                    G_io_apdu_buffer[tx] = 0x30;
                    tx += G_io_apdu_buffer[tx+1] + 2;

                    THROW(0x9000);
                    break;
                case 0x13:
                    //IMPORT STATE FROM HOST APP

                    //get the state_nonce: first 8 bytes of the payload (following the opcode 0813)
                    tx = 2;
                    os_memmove(&state_nonce, G_io_apdu_buffer + tx, sizeof(state_nonce));
                    isector = read(&N_nvm_sector); 
                    if (state_nonce != isector.nonce){
                        //invalid state, state_nonce should be the last one exported, return 0;
                        G_io_apdu_buffer[0] = 0x01;
                        tx = 1;
                        //THROW(SW_INVALID_DATA);
                        THROW(0x9000);
                        break;
                    }

                    tx += sizeof(state_nonce);

                    //get the timestamp: the 8 bytes following the state_nonce
                    os_memmove(&state_timestamp, G_io_apdu_buffer + tx, sizeof(state_timestamp));
                    tx += sizeof(state_timestamp);

                    //get the state roothash: the remaining bytes bytes following the timestamp
                    os_memmove(&state_roothash, G_io_apdu_buffer + tx, sizeof(state_roothash));
                    tx += sizeof(state_roothash);

                    //VERIFY THE SIGNATURE

                    //generate the hash from (role,state_nonce, timestamp)
                    role = ROLE_STATE_EXPORT_IMPORT;

                    cx_sha256_init(&sha);
                    cx_hash(&sha.header, 0, &role, 1, NULL); //initialize with the role byte

                    //add the state_nonce to the data to be hashed
                    cx_hash(&sha.header, 0, &state_nonce , sizeof(state_nonce), NULL);

                    //get the current time, add to data to be hashed
                    cx_hash(&sha.header, 0, &state_timestamp, sizeof(state_timestamp), NULL);

                    //add the state_roothash to data to be hashed and hash them all (role_byte,state_nonce,timestamp,state_roothash)
                    cx_hash(&sha.header, CX_LAST, &state_roothash, sizeof(state_roothash), hash);


                    //get the signature length, init a temp pubkey and verify the signature 
                    signatureLength = G_io_apdu_buffer[tx+1] + 2;

                    //get the session public key from the private key stored in flash memory
                    cx_ecfp_generate_pair(CX_CURVE_256K1, &publicKey, &N_privateKey, 1);

                    //cx_ecfp_init_public_key(CX_CURVE_256K1, &publicKey,sizeof(publicKey), &tmpPublic);

                    if (!cx_ecdsa_verify(&publicKey, CX_LAST, CX_SHA256, hash, 32,
                         G_io_apdu_buffer + tx, signatureLength)) {
                        G_io_apdu_buffer[0] = 0x02;
                        tx = 1;
                        //THROW(SW_INVALID_DATA);
                        THROW(0x9000);
                        break;
                    }
                    //everything is valid: update the time  and return success!
                    ticks = state_timestamp;
                    os_memmove(&roothash, &state_roothash, sizeof(state_roothash));
                    last_imported_state_nonce = state_nonce;

                    //return 1 for success!!!
                    G_io_apdu_buffer[0] = 0x00;
                    tx = 1;
                    THROW(0x9000);
                    break;
                case 0x21: // executeQueryInsert

                    // get the latest nonce(from read()) and the see if the last imported state is valid
                    isector = read(&N_nvm_sector); 
                    if ((isector.nonce > last_imported_state_nonce) || (os_memcmp(roothash, state_roothash, 32) != 0)){
                        G_io_apdu_buffer[0] = 0x50;
                        tx = 1;
                        THROW(0x9001);
                        break;
                    }


                    QI_depth = G_io_apdu_buffer[2]; // the depth of the tree (64 max: 63 down to 0)
                    os_memmove(QI_keyhash, G_io_apdu_buffer+3, 32); // unique query id 
                    os_memmove(QI_valuehash, G_io_apdu_buffer+3+32, 32);
                    os_memmove(QI_newhash, G_io_apdu_buffer+3+32+32, 32);
                    os_memmove(QI_oldhash, G_io_apdu_buffer+3+32+32+32, 32);
                    

                    if (QI_depth == 63){ 

                    //first iteration of the insertion

                        
                        QI_value_t0 = ticks; //current time
                        // get the 8-byte dt value (rx - 1 byte(nbytes) - 32 bytes(nonce) - 8 bytes (dt))
                        os_memmove(&QI_value_dt, G_io_apdu_buffer+rx-1-32-8, 8);

                        if (QI_value_dt > 5184000*10) { //not allowed (up to 60 days), one tick every 100ms, 10 ticks/sec
                            G_io_apdu_buffer[0] = 0x56;
                            tx = 1;
                            THROW(0x9001);
                            break;
                        }

                        // get the 8-byte dt value (rx - 1 byte(nbytes) - 32 bytes(nonce) )
                        os_memmove(QI_value_rnonce, G_io_apdu_buffer+rx-1-32, 32);

                        //get NBYTES -> number of random bytes to be returned
                        QI_value_nbytes = G_io_apdu_buffer[rx-1];

                        if ((QI_value_nbytes == 0)||(QI_value_nbytes > 32)) { //not allowed, should always return (1-32 bytes)
                            G_io_apdu_buffer[0] = 0x55;
                            tx = 1;
                            THROW(0x9001);
                            break;
                        }

                        // hash the (t0,dt,nonce,nbytes) tuple
                        cx_sha256_init(&sha);
                        cx_hash(&sha.header, 0, &QI_value_t0, sizeof(QI_value_t0), NULL);
                        cx_hash(&sha.header, 0, &QI_value_dt, sizeof(QI_value_dt), NULL);
                        cx_hash(&sha.header, 0, QI_value_rnonce, sizeof(QI_value_rnonce), NULL);
                        cx_hash(&sha.header, CX_LAST, &QI_value_nbytes, sizeof(QI_value_nbytes), hash);

                        // valuehash == newhash == sha256((t0,dt,nonce,nbytes))
                        os_memmove(QI_valuehash, hash, sizeof(hash));
                        os_memmove(QI_newhash, hash, sizeof(hash));

                        //QI_ZH = zero hash, SHA256("\x00"*32), maybe we should 
                        os_memmove(QI_oldhash, QI_ZH, 32);

                    } else {
                        // depth -> range(62,-1)
                        tx = 1+32+32+32+32; // till right before value args

                        // check whether the previously computed/expected hash matches
                        cx_sha256_init(&sha);
                        cx_hash(&sha.header, CX_LAST, G_io_apdu_buffer+2, tx, hash);

                        // QI_nexthash = sha256(depth,keyhash,valuhash,newhash,oldhash)
                        if (os_memcmp(QI_nexthash, hash, 32) != 0){
                            G_io_apdu_buffer[0] = 0x54;
                            tx = 1;
                            THROW(0x9001);
                            break;
                        }


                    }

                    if (QI_depth == 255){

                        //leaf node, 255 == -1 (unigned int), last step

                        if (os_memcmp(roothash, QI_oldhash, 32) != 0){
                            G_io_apdu_buffer[0] = 0x52;
                            os_memmove(G_io_apdu_buffer+1, roothash, 32);
                            os_memmove(G_io_apdu_buffer+1+32, QI_oldhash, 32);
                            tx = 1+32+32;
                            THROW(0x9001);
                            break;
                        } else {
                            //finish!
                            os_memmove(roothash, QI_newhash, 32); // now you should export the state..

                            G_io_apdu_buffer[0] = 0xff;
                            G_io_apdu_buffer[1] = 0xff;
                            G_io_apdu_buffer[2] = 0xff;
                            G_io_apdu_buffer[3] = 0xff;
                            //os_memmove(G_io_apdu_buffer+4, roothash, 32);
                            ////sign(markerbyte_2, keyhash, valuehash) & terminate

                            tx = 4;//+32;




                            os_memmove(G_io_apdu_buffer+4, QI_keyhash, 32);
                            tx += 32;
                            os_memmove(G_io_apdu_buffer+4+32, QI_valuehash, 32);
                            tx += 32;

                            cx_sha256_init(&sha);
                            cx_hash(&sha.header, CX_LAST, G_io_apdu_buffer, tx, hash);

                            //sign with the session private key
                            cx_ecdsa_sign(&N_privateKey, CX_LAST | CX_RND_RFC6979,
                              CX_SHA256, hash, 32, G_io_apdu_buffer + tx);

                            tx += G_io_apdu_buffer[tx+1] + 2;



                            THROW(0x9000);
                            break;
                        }
                    } else {

                        //get the offset: we need only one nibble (half byte) for indexing, depending on if it's the 1st or 2nd half
                        //we shift 4-bits right(when we need the 4 MSB-> 1st half) and then zero the 4 MSB
                        QI_nodeOffset = (QI_keyhash[QI_depth/2] >> 4*((QI_depth+1)%2)) & 0x0f;

                        //check if.. old_node[keyhash[depth]] == old_hash. If not.. ERROR
                        // check if the node about to be updated has the expected value
                        if (os_memcmp(oldNode+32*QI_nodeOffset, QI_oldhash, 32) != 0){
                          G_io_apdu_buffer[0] = 0x53;
                          G_io_apdu_buffer[1] = QI_nodeOffset;
                          os_memmove(G_io_apdu_buffer+1+1, oldNode+32*QI_nodeOffset, 32);
                          tx = 1+1+32;
                          THROW(0x9001);
                          break;
                        }
                        
                        //new_old_hash = H(old_node)
                        // store the hash of the node before the update
                        cx_sha256_init(&sha);
                        cx_hash(&sha.header, CX_LAST, &oldNode, sizeof(oldNode), hash);
                        os_memmove(QI_new_oldhash, &hash, sizeof(hash));

                        //old_node[keyhash[depth]] = newhash #new_node
                        // update the node with the  hash of the new value
                        // valuehash == newhash == sha256((t0,dt,nonce,nbytes)) if depth ==63
                        os_memmove(oldNode+32*QI_nodeOffset, QI_newhash, 32);

                        QI_depth--;
                        os_memmove(QI_oldhash, QI_new_oldhash, 32); // redundant? move QI_oldhash above

                        // get the hash of the updated node -> store it in QI_newhash
                        cx_sha256_init(&sha);
                        cx_hash(&sha.header, CX_LAST, &oldNode, sizeof(oldNode), hash);
                        os_memmove(QI_newhash, &hash, sizeof(hash));
                        
                        // return to Host app:
                        G_io_apdu_buffer[0] = QI_depth; //decreased depth
                        os_memmove(G_io_apdu_buffer+1, QI_keyhash, 32); //the keyhash
                        os_memmove(G_io_apdu_buffer+1+32, QI_valuehash, 32); //the new value inserted in the node
                        os_memmove(G_io_apdu_buffer+1+32+32, QI_newhash, 32); //the new updated hash value of the full node
                        os_memmove(G_io_apdu_buffer+1+32+32+32, QI_oldhash, 32); //the old/previous hash value of the node before the insertion
                        tx = 1+32+32+32+32;
			

                        // hash the buffer contents and store it in QI_nexthash
                        // QI_nexthash = sha256(depth,keyhash,valuhash,newhash,oldhash)
                        cx_sha256_init(&sha);
                        cx_hash(&sha.header, CX_LAST, G_io_apdu_buffer, tx, hash);

                        os_memmove(QI_nexthash, &hash, sizeof(hash));


                        if (QI_depth+1 == 63){
                            //if first iteration
                            os_memmove(G_io_apdu_buffer+tx, &QI_value_t0, sizeof(QI_value_t0));
                            tx += 8;
                            os_memmove(G_io_apdu_buffer+tx, &QI_value_dt, sizeof(QI_value_dt));
                            tx += 8;
                            os_memmove(G_io_apdu_buffer+tx, QI_value_rnonce, sizeof(QI_value_rnonce));
                            tx += 32;
                            G_io_apdu_buffer[tx] = QI_value_nbytes;
                            tx += 1;
                            os_memmove(G_io_apdu_buffer+tx, QI_valuehash, sizeof(QI_valuehash));
                            tx += 32;
                        }
                        else{
                          
                          G_io_apdu_buffer[tx] = QI_nodeOffset;
                          tx += 1;
                          os_memmove(G_io_apdu_buffer+tx, QI_newhash, 32);
                          tx += 32;
                        }
                        THROW(0x9000);
                        break;
                    }
                    tx = 0;
                    THROW(0x9000);
                    break;

                case 0x22: 
                //RNG - for a given query this function returns a random byte array in adeterministic way
                    os_memmove(EX_keyhash, G_io_apdu_buffer+2+4, 32);
                    os_memmove(EX_valuehash, G_io_apdu_buffer+2+4+32, 32);

                    os_memmove(&EX_value_t0, G_io_apdu_buffer+2+4+32+32, 8);
                    os_memmove(&EX_value_dt, G_io_apdu_buffer+2+4+32+32 +8, 8);
                    os_memmove(EX_value_rnonce, G_io_apdu_buffer+2+4+32+32 +8+8, 32);
                    EX_value_nbytes = G_io_apdu_buffer[2+4+32+32 +8+8+32];

                    //VERIFY value args hash match with signed hash
                    cx_sha256_init(&sha);
                    cx_hash(&sha.header, CX_LAST, G_io_apdu_buffer+2+4+32+32, 8+8+32+1, hash);
                    if (os_memcmp(EX_valuehash, hash, 32) != 0){
                        G_io_apdu_buffer[0] = 0x01;
                        tx = 1;
                        THROW(0x6D00);
                        break;
                    }
                    

                    //VERIFY THE SIGNATURE

                    cx_sha256_init(&sha);

                    cx_hash(&sha.header, CX_LAST, G_io_apdu_buffer+2, 4+32+32, hash);

                    //get the signature length, init a temp pubkey and verify the signature
                    // last byte added (+1) is to get the  sig length (stored in the second byte of the sig )
                    signatureLength = G_io_apdu_buffer[2+4+32+32+ 8+8+32+1 +1] + 2;

                    //get the session public key from the private key stored in flash memory
                    cx_ecfp_generate_pair(CX_CURVE_256K1, &publicKey, &N_privateKey, 1);

                    // Check wether the data given were the ones originally signed by the session key
                    if (!cx_ecdsa_verify(&publicKey, CX_LAST, CX_SHA256, hash, 32,
                         G_io_apdu_buffer + 2+4+32+32 +8+8+32+1, signatureLength)) {
                        G_io_apdu_buffer[0] = 0x02;
                        tx = 1;
                        THROW(0x6D00);
                        break;
                    }


                    // ALL GOOD!!!!
                    //Check if the requested time delay (dt) has passed
                    EX_value_t1 = EX_value_t0+EX_value_dt;
                    if (ticks < EX_value_t1){ //TOO EARLY
                        G_io_apdu_buffer[0] = 0x03;
                        os_memmove(G_io_apdu_buffer+1, &ticks, 8);
                        os_memmove(G_io_apdu_buffer+1+8, &EX_value_t1, 8);
                        tx = 1+8+8;
                        THROW(0x6D00);
                        break;
                    }


                    G_io_apdu_buffer[0] = 0x88;
                    tx = 1;

                    // store to EX_tosign the data to be hashed, then hash them, sign the hash and hash the signature

                    // hash(keyhash, dt, nbytes, nonce)
                    os_memmove(EX_tosign, EX_keyhash, sizeof(EX_keyhash));
                    os_memmove(EX_tosign+sizeof(EX_keyhash), &EX_value_dt, sizeof(EX_value_dt));
                    EX_tosign[sizeof(EX_keyhash)+sizeof(EX_value_dt)] = EX_value_nbytes;
                    os_memmove(EX_tosign+sizeof(EX_keyhash)+sizeof(EX_value_dt)+sizeof(EX_value_nbytes), EX_value_rnonce, sizeof(EX_value_rnonce));

                    cx_sha256_init(&sha);
                    cx_hash(&sha.header, CX_LAST, EX_tosign, sizeof(EX_tosign), hash);

                    // signature = sign(hash(keyhash, dt, nbytes, nonce))
                    cx_ecdsa_sign(&N_privateKey, CX_LAST | CX_RND_RFC6979,
                        CX_SHA256, hash, sizeof(hash), EX_signature);

                    // sig_hash = hash(signature)
                    cx_sha256_init(&sha);
                    cx_hash(&sha.header, CX_LAST, EX_signature, EX_signature[1]+2, hash);

                    // store sig_hash to buffer
                    os_memmove(G_io_apdu_buffer+1, hash, EX_value_nbytes);
                    tx += EX_value_nbytes;
                    // store signature to buffer and return
                    os_memmove(G_io_apdu_buffer+tx, EX_signature, EX_signature[1]+2);
                    tx += EX_signature[1]+2;


                    THROW(0x9000);
                    break;
                case 0x30: // getOldNodeHash
                    cx_sha256_init(&sha);
                    cx_hash(&sha.header, CX_LAST, &oldNode, sizeof(oldNode), hash);
                    os_memmove(G_io_apdu_buffer, &hash, sizeof(hash));
                    tx = sizeof(hash);
                    THROW(0x9000);
                    break;
                case 0x31: // setOldNode_1
                    // get and store the first 6 node elements (hashes), 32 bytes each
                    os_memmove(oldNode+32*6*0, G_io_apdu_buffer+2, 32*6);
                    tx = 0;
                    THROW(0x9000);
                    break;
                case 0x32: // setOldNode_2
                    // get and store another 6 node elements (hashes), 32 bytes each
                    os_memmove(oldNode+32*6*1, G_io_apdu_buffer+2, 32*6);
                    tx = 0;
                    THROW(0x9000);
                    break;
                case 0x33: // setOldNode_3
                    // get and store the last 4 node elements (hashes), 32 bytes each (16 in total)
                    os_memmove(oldNode+32*6*2, G_io_apdu_buffer+2, 32*4);
                    tx = 0;
                    THROW(0x9000);
                    break;
                case 0xFF: // return to dashboard
                    os_sched_exit(0);

                default:
                    THROW(0x6D00);
                    break;
                }
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                case 0x6000:
                case 0x9000:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}

void io_seproxyhal_display(const bagl_element_t *element) {
    return io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        UX_DISPLAYED_EVENT({});
        break;
    case SEPROXYHAL_TAG_TICKER_EVENT:
        //gets triggered every 100ms
        ticks_increase();
        break;
    // unknown events are acknowledged
    default:
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }
    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    UX_INIT();

    // ensure exception will work as planned
    os_boot();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

            //generate a new session keypair, it should be done only once when the application is first deployed
             if (N_initialized.initialized != 0x01) {
                uint8_t canary;
                cx_ecfp_private_key_t privateKey;
                cx_ecfp_public_key_t publicKey;
                cx_ecfp_generate_pair(CX_CURVE_256K1, &publicKey, &privateKey,
                                      0);
                nvm_write(&N_privateKey, &privateKey, sizeof(privateKey));
                canary = 0x01;
                nvm_write(&N_initialized.initialized, &canary, sizeof(canary));
            }

            USB_power(1);

            ui_idle();

            rng_main();
        }
        CATCH_OTHER(e) {
        }
        FINALLY {
        }
    }
    END_TRY;

    app_exit();
}
