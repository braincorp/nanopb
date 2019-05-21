/* Attempts to test all the datatypes supported by ProtoBuf.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pb_encode.h>
#include "alltypes.pb.h"
#include "test_helpers.h"

int main(int argc, char **argv)
{
    // int mode = (argc > 1) ? atoi(argv[1]) : 0;
    // int mode = 1;
    
    /* Initialize the structure with constants */
    AllTypes alltypes = AllTypes_init_zero;
    
    alltypes.req_int32         = -1001;
    alltypes.req_uint32        = 1003;
    alltypes.req_sint32        = -1005;
    alltypes.req_bool          = true;
    
    alltypes.req_fixed32       = 1008;
    alltypes.req_sfixed32      = -1009;
    alltypes.req_float         = 1010.0f;
    
    strcpy(alltypes.req_string, "1014");
    alltypes.req_bytes.size = 4;
    memcpy(alltypes.req_bytes.bytes, "1015", 4);
    strcpy(alltypes.req_submsg.substuff1, "1016");
    alltypes.req_submsg.substuff2 = 1016;
    alltypes.req_submsg.substuff3 = 3;
    alltypes.req_enum = MyEnum_Truth;
    memcpy(alltypes.req_fbytes, "1019", 4);
    
    alltypes.rep_int32_count = 5; alltypes.rep_int32[4] = -2001;
    alltypes.rep_uint32_count = 5; alltypes.rep_uint32[4] = 2003;
    alltypes.rep_sint32_count = 5; alltypes.rep_sint32[4] = -2005;
    alltypes.rep_bool_count = 5; alltypes.rep_bool[4] = true;
    
    alltypes.rep_fixed32_count = 5; alltypes.rep_fixed32[4] = 2008;
    alltypes.rep_sfixed32_count = 5; alltypes.rep_sfixed32[4] = -2009;
    alltypes.rep_float_count = 5; alltypes.rep_float[4] = 2010.0f;
    
    alltypes.rep_string_count = 5; strcpy(alltypes.rep_string[4], "2014");
    alltypes.rep_bytes_count = 5; alltypes.rep_bytes[4].size = 4;
    memcpy(alltypes.rep_bytes[4].bytes, "2015", 4);

    // alltypes.rep_submsg_count = 5;
    // strcpy(alltypes.rep_submsg[4].substuff1, "2016");
    // alltypes.rep_submsg[4].substuff2 = 2016;
    // alltypes.rep_submsg[4].substuff3 = 2016;
    
    alltypes.rep_enum_count = 5; alltypes.rep_enum[4] = MyEnum_Truth;
    alltypes.rep_emptymsg_count = 5;
    
    alltypes.rep_fbytes_count = 5;
    memcpy(alltypes.rep_fbytes[4], "2019", 4);
    
    alltypes.req_limits.int32_min  = INT32_MIN;
    alltypes.req_limits.int32_max  = INT32_MAX;
    // alltypes.req_limits.uint32_min = 0;
    alltypes.req_limits.uint32_max = UINT32_MAX;
    alltypes.req_limits.enum_min   = HugeEnum_Negative;
    alltypes.req_limits.enum_max   = HugeEnum_Positive;
    
    alltypes.opt_int32         = 3041;
    alltypes.opt_uint32        = 3043;
    alltypes.opt_sint32        = 3045;
    alltypes.opt_bool          = true;
    
    alltypes.opt_fixed32       = 3048;
    alltypes.opt_sfixed32      = 3049;
    alltypes.opt_float         = 3050.0f;
    
    strcpy(alltypes.opt_string, "3054");
    alltypes.opt_bytes.size = 4;
    memcpy(alltypes.opt_bytes.bytes, "3055", 4);
    // strcpy(alltypes.opt_submsg.substuff1, "3056");
    // alltypes.opt_submsg.substuff2 = 3056;
    alltypes.opt_enum = MyEnum_Truth;
    memcpy(alltypes.opt_fbytes, "3059", 4);

    //alltypes.which_oneof = AllTypes_oneof_msg1_tag;
    //strcpy(alltypes.oneof.oneof_msg1.substuff1, "4059");
    //alltypes.oneof.oneof_msg1.substuff2 = 4059;
    
    // alltypes.end = 1099;
    
    {
        uint8_t buffer[AllTypes_size];
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
        
        /* Now encode it and check if we succeeded. */
        if (pb_encode(&stream, AllTypes_fields, &alltypes))
        {
            SET_BINARY_MODE(stdout);
            fwrite(buffer, 1, stream.bytes_written, stdout);
            return 0; /* Success */
        }
        else
        {
            fprintf(stderr, "Encoding failed: %s\n", PB_GET_ERROR(&stream));
            return 1; /* Failure */
        }
    }
}
