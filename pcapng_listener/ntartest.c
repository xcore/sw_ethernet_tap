/*
 * ntartest.c
 *
 *  $Id: ntartest.c 13 2008-01-10 17:35:21Z jyoung $
 *
 * Copyright 2008 Jim Young 
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * ====
 *
 * This is an extemely simple minded utility to test certain 
 * charteristics regarding the block headers of the ntar (aka 
 * PcapNG) file format.
 *
 * It really only pays attention to the block headers.  It does 
 * not try to parse or validate that the payload types are well
 * formed nor if the block trailers are consistent with their
 * respective block headers.
 *
 * An ntar file consists of a series of variable length blocks.
 * Each block consists of two mandatory components a block header
 * (8 octets) and a block trailer (4 octets), and may optionally
 * contain a payload.
 *
 * The block header consists of two 32 bit components:
 *   A block type (32 bits (4 octets))
 *   A block length (32 bits (4 octets))
 *
 * The block trailer conists of one 32 bit component:
 *   The block length (32 bits (4 octets))
 *
 * Therefore a minimum length block (i.e. a block with no 
 * payload) is 12 octets in length.
 * 
 * If the optional payload is prosent it must contain one or 
 * more octets of data.
 *
 * The actual length of a block must be evenly divisable by four.
 * 
 * If the number of data octets is not a multiple of four, then
 * 1 to 3 padding bytes (NUL characters) must be inserted after
 * the last payload byte and before the block trailer.
 *
 * Please note that the reported block length (the block length
 * written into the block header and block trailer) MAY be 1 to 
 * 3 octets less that the actual blocklength due to the padding.
 *
 * NOTE: The discepency of the reported block length versus the 
 * actual block length could arguably be be considered a defect 
 * in the current ntar spec and could possible be corrected.  
 * Each of currently defined payloads have their own header 
 * structure and in theory would indicate payloads whose
 * length is not evenly divisable by 4.  Would could argue that
 * the blockLength filed should always directly indicate the 
 * actual length of the block.
 *
 * For the offical ntar/pcapng format see:
 *
 *   http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
 */

#include <stdio.h>

/*
 * The following typedef name (gunit32) was "borrowed" from glib 
 * which is defines the guint32 as follows:
 *
 * "An unsigned integer guaranteed to be 32 bits on all platforms. 
 * Values of this type can range from 0 to 4,294,967,295."
 *
 * WARNING: Within this context of this little source module the 
 * above compile time claim of the byte width is NOT assured!!! 
 * A startup runtime test within this source attempts to verify 
 * that this gunit32 is really 32 bits wide.
 */

typedef unsigned int guint32;

/*
 * defines
 */

#define min(a, b) ((a) > (b) ? (b) : (a)) 

#define ENDIAN_MAGIC 0x1A2B3C4D

#define READ_START_OF_FILE 1
#define READ_BLOCK_HEADER 2
#define READ_MAGIC 3
#define READ_DATA 4


#define ENDIAN_UNKNOWN  0
#define ENDIAN_BIG      1
#define ENDIAN_LITTLE   2

struct ntarHeader {
    guint32 blockType;
    guint32 blockLength;
};

/*
 * prototypes
 */

static guint32 GetDataWord(int /* mySystemEndianness */ , int /* endiantype */ , unsigned char * /* data */ );
static int ReadBlockHeader(FILE * /* myFile */ , struct ntarHeader * /* myHeader */ );
static int GetSystemEndianness(void);
static int GetSectionEndianness(unsigned char * /* inData */ );

/*
 * globals
 */

unsigned char myBuffer[4096];

/*
 * main():
 */

int main(int argc, char *argv[])
{
    guint32 blockType = 0;
    guint32 blockTotalStart = 0;
    guint32 blockTotalEnd = 0;
    FILE *myFile;
    char *myFileName;
    int readLength;
    guint32 totalRead = 0;
    int nextRead = READ_START_OF_FILE;
    int myBlockType = 0;
    guint32 myDataWord;
    struct ntarHeader myHeader;
    int mySystemEndianness;
    int mySectionEndianness;
    int blockEndianType = 0;
    unsigned adjustedBlockLength;
    guint32 blockNumber = 0;

    if (argc != 2) {
        printf("Usage: ntartest FILENAME\n");
        exit(1);    
    }

    myFileName = argv[1];
 
    mySystemEndianness = GetSystemEndianness();

    if ( sizeof(guint32) != 4 ) {
        printf ("oops: sizeof guint32 (in octets) = %d, which is not 4 (32 bits)!\n", sizeof(guint32)); 
        exit(99);
    }

    myFile = fopen(myFileName, "rb");

    if(myFile == NULL) {
         printf("Could not open file \"%s\"\n", myFileName);
         exit(99);
    }

    printf("+++Working on file: %s\n", myFileName);

    switch(mySystemEndianness)
    {
        case ENDIAN_BIG: {
            printf("This machine is big-endian.\n");
            break;
        }
        case ENDIAN_LITTLE: {
            printf("This machine is little-endian.\n");
            break;
        }
        case ENDIAN_UNKNOWN: {
            printf("Endianness for this machine could not be determined.\n");
            exit(99);
            break;
        }
        default: {
            printf("Unexpected endianness value %d (%0x).\n", mySystemEndianness, mySystemEndianness);
            exit(99);
            break;
        }
    }
             
    while(!feof(myFile)) {

        readLength = ReadBlockHeader(myFile, &myHeader);

        if(readLength < 8) {
            if(readLength == 0 && feof(myFile))
                 break;

            printf ("Oops: short read, should have read 8 bytes, only read %d, are we reading from a pipe or an open file?.\n", \
                    readLength);
            exit(99);
        }

        blockNumber++;

        if (myHeader.blockType == 0x0a0d0d0a) {
            readLength = fread(myBuffer, 1, 4, myFile);

            if (readLength != 4) {
                printf ("Oops: short read, should have read %d bytes, only read %d.\n", 4, readLength);
                exit(99);
            }

            mySectionEndianness = GetSectionEndianness(myBuffer);

            switch(mySectionEndianness)
            {
                case ENDIAN_BIG: {
                    printf("This section is big-endian.\n");
                    break;
                }
                case ENDIAN_LITTLE: {
                    printf("This section is little-endian.\n");
                    break;
                }
                case ENDIAN_UNKNOWN: {
                    printf("Endianness for this section could not be determined.\n");
                    break;
                }
                default: {
                    printf("Unexpected endianness value %d (%0x).\n", mySectionEndianness, mySectionEndianness);
                    break;
                }
            }
        }
             
        myHeader.blockType = GetDataWord(mySystemEndianness, mySectionEndianness, (unsigned char *)&myHeader.blockType);
        myHeader.blockLength = GetDataWord(mySystemEndianness, mySectionEndianness, (unsigned char *)&myHeader.blockLength);

        printf("\n");

        switch(myHeader.blockType)
        {
             case 0x00000001: /* Interface Description Block */
                 printf("%08x: Block #%u, Type = Interface Description Block (%08x)\n", totalRead, blockNumber, myHeader.blockType);
                 break;
             case 0x00000002: /* Packet Block */
                 printf("%08x: Block #%u, Type = Packet Block (%08x)\n", totalRead, blockNumber, myHeader.blockType);
                 break;
             case 0x00000003: /* Simple Packet Block */
                 printf("%08x: Block #%u, Type = Simple Packet Block (%08x)\n", totalRead, blockNumber, myHeader.blockType);
                 break;
             case 0x00000004: /* Name Resolution Block */
                 printf("%08x: Block #%u, Type = Name Resolution Block (%08x)\n", totalRead, blockNumber, myHeader.blockType);
                 break;
             case 0x00000005: /* Interface Statistics Block */
                 printf("%08x: Block #%u, Type = Interface Statistics Block (%08x)\n", totalRead, blockNumber, myHeader.blockType);
                 break;
             case 0x00000006: /* Enhanced Packet Block */
                 printf("%08x: Block #%u, Type = Enhanced Packet Block (%08x)\n", totalRead, blockNumber, myHeader.blockType);
                 break;
             case 0x0a0d0d0a: /* Section Header Block */
                 printf("%08x: Block #%u, Type = Section Header Block (%08x)\n", totalRead, blockNumber, myHeader.blockType);
                 break;
             default:
                 if (myHeader.blockType == 0x0a0a0d0a
                 || (myHeader.blockType >= 0x0a0d0a00 && myHeader.blockType <= 0x0a0d0aff)
                 || (myHeader.blockType >= 0x0d0d0a00 && myHeader.blockType <= 0x0d0d0aff)) {
                     printf("%08x: Corrupted Section header. (%08x)\n", totalRead, myHeader.blockType);
                     exit(99);
                 } else {
                     printf("%08x: Unknown Block Type (%08x)\n", totalRead, myHeader.blockType);
                 }
        }

        totalRead += 4;

        /*
         * adjusted block length
         *
         * A non-obvious characteristic of the current ntar blocklength is
         * that blocklength MAY not actually indicate the length of the
         * actual data block (the payload).  If the number of payload 
         * octets is NOT evenly divisable by four (4) then the one or 
         * more padding bytes will have been added after the payload and 
         * before the blocktrailer to pad the length of the payload to a
         * 32 bit boundry.  To seek forwards or backwards to the next or 
         * previous block one will need to add from 0 to 3 to the reported 
         * blockLength to detremine where the next block will start.
         */

        adjustedBlockLength = myHeader.blockLength;

        switch(adjustedBlockLength % 4)
        {
             case 0:
                 printf("+++ blockLength %% 4 = 0, no pad bytes\n");
                 break;
             case 1:
                 printf("+++ blockLength %% 4 = 1, add 3 pad bytes\n");
                 adjustedBlockLength +=3;
                 break;
             case 2:
                 printf("+++ blockLength %% 4 = 2, add 2 pad bytes\n");
                 adjustedBlockLength +=2;
                 break;
             case 3:
                 printf("+++ blockLength %% 4 = 3, add 1 pad bytes\n");
                 adjustedBlockLength +=1;
                 break;
             default:
                 printf("+++ Unexpected remainder: %d\n", adjustedBlockLength % 4);
                 break;
        }

        printf("%08x: Reported Block Length %u (%08x), Adjusted Block Length %u (%08x), next block at offset %08x\n", \
                 totalRead, \
                 myHeader.blockLength, \
                 myHeader.blockLength, \
                 adjustedBlockLength, \
                 adjustedBlockLength, \
                 totalRead + ( adjustedBlockLength - 4));

        totalRead += 4;

        printf("%08x: Remainder of Block Data (%08x) bytes\n", totalRead, (adjustedBlockLength - 8), (adjustedBlockLength - 8));

        /*
         * Read in the rest of the block of data.
         *
         * Note: The following assumes that the payload will NOT exceed 
         * 4096 bytes.  A real program would have read loop that wouldn't 
         * break until the entire block in consumed.
         */

        if(myHeader.blockType == 0x0a0d0d0a) {
            readLength = fread(&myBuffer[4], 1, min((adjustedBlockLength - 12), 4096), myFile);

            if (readLength != (adjustedBlockLength - 12)) {
                    printf ("Oops: short read, should have read %d bytes, only read %d.\n",
                            (adjustedBlockLength - 12), readLength);
                    exit(99);
            }
             
        } else {
            readLength = fread(myBuffer, 1, min((adjustedBlockLength - 8), 4096), myFile);

            if (readLength != (adjustedBlockLength - 8)) {
                    printf ("Oops: short read, should have read %d bytes, only read %d.\n",
                            (adjustedBlockLength - 8), readLength);
                    exit(99);
            }
        }

        totalRead += readLength;
    }

    fclose(myFile);

    myFile = NULL;

    return 0;
}

/*
 * GetDataWord():
 */

static guint32 GetDataWord(int mySystemEndianness, int endianType, unsigned char *inData)
{
    union {
        guint32 l;
        char c[sizeof(guint32)];
    } ul;

    if(mySystemEndianness == endianType) {
        ul.c[0] = inData[0];
        ul.c[1] = inData[1];
        ul.c[2] = inData[2];
        ul.c[3] = inData[3];
    } else {
        ul.c[0] = inData[3];
        ul.c[1] = inData[2];
        ul.c[2] = inData[1];
        ul.c[3] = inData[0];
    }

    return ul.l;
}


/*
 * ReadBlockHeader():
 */

static int ReadBlockHeader(FILE *myFile, struct ntarHeader *myHeader) 
{
    return  fread(myHeader, 1, sizeof(struct ntarHeader), myFile); 
}

/*
 * GetSystemEndianness():
 *
 * Adapted from wikipedia:
 * http://en.wikipedia.org/wiki/Endianness
 */

static int GetSystemEndianness(void)
{
    union {
        short s;
        char c[sizeof(short)];
    } un;

    un.s = 0x0102;

    if(sizeof(short) == 2)
    {
        if(un.c[0] == 1 && un.c[1] == 2)
            return ENDIAN_BIG;
        else if(un.c[0] == 2 && un.c[1] == 1)
            return ENDIAN_LITTLE;
        else
            return ENDIAN_UNKNOWN;
    }
    else
    {
        return ENDIAN_UNKNOWN;
    }
}


/*
 * GetSectionEndianness():
 */

static int GetSectionEndianness(unsigned char *inData)
{
    if (inData[0] == 0x1a && inData[1] == 0x2b && inData[2] == 0x3c && inData[3] == 0x4d) {
        return ENDIAN_BIG;
    } else if (inData[0] == 0x4d && inData[1] == 0x3c && inData[2] == 0x2b && inData[3] == 0x1a) {
        return ENDIAN_LITTLE;
    } else {
        return ENDIAN_UNKNOWN;
    }
}

