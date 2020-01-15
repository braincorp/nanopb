/* pb_encode.c -- encode a protobuf using minimal resources
 *
 * 2011 Petteri Aimonen <jpa@kapsi.fi>
 */

#include "pb.h"
#include "pb_encode.h"
#include "pb_common.h"

/* Use the GCC warn_unused_result attribute to check that all return values
 * are propagated correctly. On other compilers and gcc before 3.4.0 just
 * ignore the annotation.
 */
#if !defined(__GNUC__) || ( __GNUC__ < 3) || (__GNUC__ == 3 && __GNUC_MINOR__ < 4)
    #define checkreturn
#else
    #define checkreturn __attribute__((warn_unused_result))
#endif

/**************************************
 * Declarations internal to this file *
 **************************************/
typedef bool (*pb_encoder_t)(pb_ostream_t *stream, const pb_field_t *field, const void *src) checkreturn;

static bool checkreturn buf_write(pb_ostream_t *stream, const pb_byte_t *buf, size_t count);
static bool checkreturn encode_array(pb_ostream_t *stream, const pb_field_t *field, const void *pData, size_t count, pb_encoder_t func);
static bool checkreturn encode_field(pb_ostream_t *stream, const pb_field_t *field, const void *pData);
static void *pb_const_cast(const void *p);
static bool checkreturn pb_enc_varint(pb_ostream_t *stream, const pb_field_t *field, const void *src);
static bool checkreturn pb_enc_uvarint(pb_ostream_t *stream, const pb_field_t *field, const void *src);
static bool checkreturn pb_enc_svarint(pb_ostream_t *stream, const pb_field_t *field, const void *src);
static bool checkreturn pb_enc_fixed32(pb_ostream_t *stream, const pb_field_t *field, const void *src);
static bool checkreturn pb_enc_fixed64(pb_ostream_t *stream, const pb_field_t *field, const void *src);
static bool checkreturn pb_enc_bytes(pb_ostream_t *stream, const pb_field_t *field, const void *src);
static bool checkreturn pb_enc_string(pb_ostream_t *stream, const pb_field_t *field, const void *src);
static bool checkreturn pb_enc_submessage(pb_ostream_t *stream, const pb_field_t *field, const void *src);
static bool checkreturn pb_enc_fixed_length_bytes(pb_ostream_t *stream, const pb_field_t *field, const void *src);
bool pb_find_tag(pb_field_iter_t *p_iter, pb_size_t tag_to_find, uint16_t max_num_fields);

#ifdef PB_WITHOUT_64BIT
#define pb_int64_t int32_t
#define pb_uint64_t uint32_t

static bool checkreturn pb_encode_negative_varint(pb_ostream_t *stream, pb_uint64_t value);
#else
#define pb_int64_t int64_t
#define pb_uint64_t uint64_t
#endif

// This is the max value that will fit in a varint byte
#define VARINT_ONE_BYTE 0x7F

/* --- Function pointers to field encoders ---
 * Order in the array must match pb_action_t LTYPE numbering.
 */
static const pb_encoder_t PB_ENCODERS[PB_LTYPES_COUNT] = {
    &pb_enc_varint,
    &pb_enc_uvarint,
    &pb_enc_svarint,
    &pb_enc_fixed32,
    &pb_enc_fixed64,
    
    &pb_enc_bytes,
    &pb_enc_string,
    &pb_enc_submessage,
    NULL, /* extensions */
    &pb_enc_fixed_length_bytes
};

/*******************************
 * pb_ostream_t implementation *
 *******************************/

static bool checkreturn buf_write(pb_ostream_t *stream, const pb_byte_t *buf, size_t count)
{
    size_t i;
    pb_byte_t *dest = (pb_byte_t*)stream->state;
    stream->state = dest + count;
    
    for (i = 0; i < count; i++)
        dest[i] = buf[i];
    
    return true;
}

pb_ostream_t pb_ostream_from_buffer(pb_byte_t *buf, size_t bufsize)
{
    pb_ostream_t stream;
#ifdef PB_BUFFER_ONLY
    stream.callback = (void*)1; /* Just a marker value */
#else
    stream.callback = &buf_write;
#endif
    stream.state = buf;
    stream.max_size = bufsize;
    stream.bytes_written = 0;
#ifndef PB_NO_ERRMSG
    stream.errmsg = NULL;
#endif
    return stream;
}

bool checkreturn pb_write(pb_ostream_t *stream, const pb_byte_t *buf, size_t count)
{
    if (stream->callback != NULL)
    {
        if (stream->bytes_written + count > stream->max_size)
            PB_RETURN_ERROR(stream, "stream full");

#ifdef PB_BUFFER_ONLY
        if (!buf_write(stream, buf, count))
            PB_RETURN_ERROR(stream, "io error");
#else        
        if (!stream->callback(stream, buf, count))
            PB_RETURN_ERROR(stream, "io error");
#endif
    }
    
    stream->bytes_written += count;
    return true;
}

/*************************
 * Encode a single field *
 *************************/

/* Encode a static array. Handles the size calculations and possible packing. */
static bool checkreturn encode_array(pb_ostream_t *stream, const pb_field_t *field,
                         const void *pData, size_t count, pb_encoder_t func)
{
    size_t i;
    const void *p;
    size_t size;
    
    if (count == 0)
        return true;

    if (PB_ATYPE(field->type) != PB_ATYPE_POINTER && count > field->array_size)
        PB_RETURN_ERROR(stream, "array max size exceeded");
    
    /* We always pack arrays if the datatype allows it. */
    if (PB_LTYPE(field->type) <= PB_LTYPE_LAST_PACKABLE)
    {
        if (!pb_encode_tag(stream, PB_WT_STRING, field->tag))
            return false;
        
        /* Determine the total size of packed array. */
        if (PB_LTYPE(field->type) == PB_LTYPE_FIXED32)
        {
            size = 4 * count;
        }
        else if (PB_LTYPE(field->type) == PB_LTYPE_FIXED64)
        {
            size = 8 * count;
        }
        else
        { 
            pb_ostream_t sizestream = PB_OSTREAM_SIZING;
            p = pData;
            for (i = 0; i < count; i++)
            {
                if (!func(&sizestream, field, p))
                    return false;
                p = (const char*)p + field->data_size;
            }
            size = sizestream.bytes_written;
        }
        
        if (!pb_encode_varint(stream, (pb_uint64_t)size))
            return false;
        
        if (stream->callback == NULL)
            return pb_write(stream, NULL, size); /* Just sizing.. */
        
        /* Write the data */
        p = pData;
        for (i = 0; i < count; i++)
        {
            if (!func(stream, field, p))
                return false;
            p = (const char*)p + field->data_size;
        }
    }
    else
    {
        p = pData;
        for (i = 0; i < count; i++)
        {
            if (!pb_encode_tag_for_field(stream, field))
                return false;

            /* Normally the data is stored directly in the array entries, but
             * for pointer-type string and bytes fields, the array entries are
             * actually pointers themselves also. So we have to dereference once
             * more to get to the actual data. */
            if (PB_ATYPE(field->type) == PB_ATYPE_POINTER &&
                (PB_LTYPE(field->type) == PB_LTYPE_STRING ||
                 PB_LTYPE(field->type) == PB_LTYPE_BYTES))
            {
                if (!func(stream, field, *(const void* const*)p))
                    return false;
            }
            else
            {
                if (!func(stream, field, p))
                    return false;
            }
            p = (const char*)p + field->data_size;
        }
    }
    
    return true;
}

/* Encode a field with static or pointer allocation, i.e. one whose data
 * is available to the encoder directly. */
static bool checkreturn encode_basic_field(pb_ostream_t *stream,
    const pb_field_t *field, const void *pData)
{
    pb_encoder_t func;
    bool implicit_has = true;
    const void *pSize = &implicit_has;
    
    func = PB_ENCODERS[PB_LTYPE(field->type)];
    
    if (field->size_offset)
    {
        /* Static optional, repeated or oneof field */
        pSize = (const char*)pData + field->size_offset;
    }

    if (PB_ATYPE(field->type) == PB_ATYPE_POINTER)
    {
        /* pData is a pointer to the field, which contains pointer to
         * the data. If the 2nd pointer is NULL, it is interpreted as if
         * the has_field was false.
         */
        pData = *(const void* const*)pData;
        implicit_has = (pData != NULL);
    }

    switch (PB_HTYPE(field->type))
    {
        case PB_HTYPE_OPTIONAL:
            if (*(const bool*)pSize)
            {
                if (!pb_encode_tag_for_field(stream, field))
                    return false;
            
                if (!func(stream, field, pData))
                    return false;
            }
            break;
        
        case PB_HTYPE_REPEATED: {
            pb_size_t count;
            if (field->size_offset != 0) {
                count = *(const pb_size_t*)pSize;
            } else {
                count = field->array_size;
            }
            if (!encode_array(stream, field, pData, count, func))
                return false;
            break;
        }
        
        case PB_HTYPE_ONEOF:
            if (*(const pb_size_t*)pSize == field->tag)
            {
                if (!pb_encode_tag_for_field(stream, field))
                    return false;

                if (!func(stream, field, pData))
                    return false;
            }
            break;
            
        default:
            PB_RETURN_ERROR(stream, "invalid field type");
    }
    
    return true;
}

/* Encode a single field of any callback or static type. */
static bool checkreturn encode_field(pb_ostream_t *stream,
    const pb_field_t *field, const void *pData)
{
    if(PB_ATYPE(field->type) == PB_ATYPE_STATIC)
    {
        return encode_basic_field(stream, field, pData);
    }
    else
    {
        PB_RETURN_ERROR(stream, "invalid field type");
    }
}

/*********************
 * Encode all fields *
 *********************/

static void *pb_const_cast(const void *p)
{
    /* Note: this casts away const, in order to use the common field iterator
     * logic for both encoding and decoding. */
    union {
        void *p1;
        const void *p2;
    } t;
    t.p2 = p;
    return t.p1;
}

// binary search of a tag within a field list
bool pb_find_tag(pb_field_iter_t *p_iter, pb_size_t tag_to_find, uint16_t max_num_fields)
{
    bool is_tag_found = false;
    int16_t low_indx = 0;
    int16_t high_indx = max_num_fields - 1;   // field id is 1 based.  convert to 0 based by subtracting 1
    int16_t curr_indx = (high_indx + low_indx)>>1;
    pb_field_t *p_curr_pos = (pb_field_t *)(p_iter->pos) + curr_indx;
    while( (!is_tag_found) && (high_indx >= low_indx) )
    {
        if (tag_to_find > p_curr_pos->tag)
        {
            low_indx = curr_indx + 1;
        }
        else if(tag_to_find < p_curr_pos->tag)
        {
            high_indx = curr_indx - 1;
        }
        else
        {
            is_tag_found = true;
            p_iter->pos += curr_indx;
        }
        curr_indx = (high_indx + low_indx)>>1;
        p_curr_pos = (pb_field_t *)p_iter->pos + curr_indx;
    }
    return(is_tag_found);
}

bool checkreturn pb_encode_one_of(pb_ostream_t *stream, const pb_field_t fields[], const void *src_struct, uint16_t max_num_fields)
{
    bool is_encode_successful = false;

    pb_field_iter_t iter;
    if (!pb_field_iter_begin(&iter, fields, pb_const_cast(src_struct)))
        return true; // Empty message type 
    
    pb_size_t tag_to_encode = 0;
    // For Static optional, repeated, or oneof field, size_offset is offset to message tag
    if (iter.pos->size_offset)
    {
        const void *p_message_tag = (const char*)(iter.pData) + iter.pos->size_offset;
        tag_to_encode = *(const pb_size_t *)(p_message_tag);
    }

    bool is_tag_found = pb_find_tag(&iter, tag_to_encode, max_num_fields);

    if(is_tag_found)
    {
        pb_encoder_t func = PB_ENCODERS[PB_LTYPE(iter.pos->type)];
        is_encode_successful = pb_encode_tag_for_field(stream, iter.pos);
        if(is_encode_successful)
        {
            is_encode_successful = func(stream, iter.pos, iter.pData);
        }
    }
    return is_encode_successful;
}

bool checkreturn pb_encode(pb_ostream_t *stream, const pb_field_t fields[], const void *src_struct)
{
    pb_field_iter_t iter;
    if (!pb_field_iter_begin(&iter, fields, pb_const_cast(src_struct)))
        return true; /* Empty message type */
    
    do {
        /* Regular field */
        if (!encode_field(stream, iter.pos, iter.pData))
            return false;
    } while (pb_field_iter_next_no_oneof(&iter));
    
    return true;
}

bool pb_get_encoded_size(size_t *size, const pb_field_t fields[], const void *src_struct)
{
    pb_ostream_t stream = PB_OSTREAM_SIZING;
    
    if (!pb_encode(&stream, fields, src_struct))
        return false;
    
    *size = stream.bytes_written;
    return true;
}

/********************
 * Helper functions *
 ********************/

#ifdef PB_WITHOUT_64BIT
bool checkreturn pb_encode_negative_varint(pb_ostream_t *stream, pb_uint64_t value)
{
  pb_byte_t buffer[10];
  size_t i = 0;
  size_t compensation = 32;/* we need to compensate 32 bits all set to 1 */

  while (value)
  {
    buffer[i] = (pb_byte_t)((value & 0x7F) | 0x80);
    value >>= 7;
    if (compensation)
    {
      /* re-set all the compensation bits we can or need */
      size_t bits = compensation > 7 ? 7 : compensation;
      value ^= (pb_uint64_t)((0xFFu >> (8 - bits)) << 25); /* set the number of bits needed on the lowest of the most significant 7 bits */
      compensation -= bits;
    }
    i++;
  }
  buffer[i - 1] &= 0x7F; /* Unset top bit on last byte */

  return pb_write(stream, buffer, i);
}
#endif

bool checkreturn pb_encode_varint(pb_ostream_t *stream, pb_uint64_t value)
{
    size_t i = 0;
    bool retval = false;
    
    if(stream->callback == NULL)
    {
        // this can happen if code is propagating through to calculate the number of bytes to write.
        if (value <= 0x7F)
        {
            stream->bytes_written++;
        }
        else
        {
            while (value)
            {
                value >>= 7;
                i++;
            }
            stream->bytes_written += i;
        }
        retval = true;
    }
    else if(stream->max_size > stream->bytes_written) 
    {
        pb_byte_t *dest = (pb_byte_t*)stream->state;
        if (value <= 0x7F)
        {
            dest[0] = (pb_byte_t)value;
            stream->bytes_written++;
            stream->state = dest + 1;
            retval = true;
        }
        else
        {
            while ((value) && (stream->max_size > stream->bytes_written))
            {
                dest[i] = (pb_byte_t)((value & 0x7F) | 0x80);
                value >>= 7;
                i++;
                stream->bytes_written ++;
            }
            dest[i-1] &= 0x7F; // Unset top bit on last byte 

            retval = true;
            if(value)
            {
                // if data still remains then we have overflowed.
                retval = false;
            }
            stream->state = dest + i;
        }
    }   
    else
    {
        retval = false;
    }
    
    return retval; 
}

bool checkreturn pb_encode_svarint(pb_ostream_t *stream, pb_int64_t value)
{
    pb_uint64_t zigzagged;
    if (value < 0)
        zigzagged = ~((pb_uint64_t)value << 1);
    else
        zigzagged = (pb_uint64_t)value << 1;
    
    return pb_encode_varint(stream, zigzagged);
}

bool checkreturn pb_encode_fixed32(pb_ostream_t *stream, const void *value)
{
    bool retval = true;
    if(stream->callback != NULL)
    {
        if(stream->bytes_written + sizeof(uint32_t) <= stream->max_size)
        {
            memcpy((uint8_t *)stream->state, (uint8_t *)value, sizeof(uint32_t));
            stream->state = (pb_byte_t*)stream->state + sizeof(uint32_t);
        }
        else
        {
            retval = false;
        }
    }

    stream->bytes_written += sizeof(uint32_t);
    return(retval);
}

#ifndef PB_WITHOUT_64BIT
bool checkreturn pb_encode_fixed64(pb_ostream_t *stream, const void *value)
{
    uint64_t val = *(const uint64_t*)value;
    pb_byte_t bytes[8];
    bytes[0] = (pb_byte_t)(val & 0xFF);
    bytes[1] = (pb_byte_t)((val >> 8) & 0xFF);
    bytes[2] = (pb_byte_t)((val >> 16) & 0xFF);
    bytes[3] = (pb_byte_t)((val >> 24) & 0xFF);
    bytes[4] = (pb_byte_t)((val >> 32) & 0xFF);
    bytes[5] = (pb_byte_t)((val >> 40) & 0xFF);
    bytes[6] = (pb_byte_t)((val >> 48) & 0xFF);
    bytes[7] = (pb_byte_t)((val >> 56) & 0xFF);
    return pb_write(stream, bytes, 8);
}
#endif

bool checkreturn pb_encode_tag(pb_ostream_t *stream, pb_wire_type_t wiretype, uint32_t field_number)
{
    pb_uint64_t tag = ((pb_uint64_t)field_number << 3) | wiretype;
    return pb_encode_varint(stream, tag);
}

bool checkreturn pb_encode_tag_for_field(pb_ostream_t *stream, const pb_field_t *field)
{
    pb_wire_type_t wiretype;
    switch (PB_LTYPE(field->type))
    {
        case PB_LTYPE_VARINT:
        case PB_LTYPE_UVARINT:
        case PB_LTYPE_SVARINT:
            wiretype = PB_WT_VARINT;
            break;
        
        case PB_LTYPE_FIXED32:
            wiretype = PB_WT_32BIT;
            break;
        
        case PB_LTYPE_FIXED64:
            wiretype = PB_WT_64BIT;
            break;
        
        case PB_LTYPE_BYTES:
        case PB_LTYPE_STRING:
        case PB_LTYPE_SUBMESSAGE:
        case PB_LTYPE_FIXED_LENGTH_BYTES:
            wiretype = PB_WT_STRING;
            break;
        
        default:
            PB_RETURN_ERROR(stream, "invalid field type");
    }
    
    return pb_encode_tag(stream, wiretype, field->tag);
}

bool checkreturn pb_encode_string(pb_ostream_t *stream, const pb_byte_t *buffer, size_t size)
{
    if (!pb_encode_varint(stream, (pb_uint64_t)size))
        return false;
    
    return pb_write(stream, buffer, size);
}

bool pb_shift_data_1_byte(pb_ostream_t *stream, uint16_t bytes_to_shift)
{
    uint16_t byte_idx = 0;
    bool retval = false;
    if(stream->state != NULL)
    {
        pb_byte_t* p_source = ((pb_byte_t*)stream->state) + bytes_to_shift;
        pb_byte_t* p_dest = p_source + 1;
        for(byte_idx = 0; byte_idx < bytes_to_shift; byte_idx++)
        {
            *p_dest = *p_source;
            p_dest--;
            p_source--;
        }
        retval = true;
    }
    return(retval);
}

bool checkreturn pb_encode_submessage(pb_ostream_t *stream, const pb_field_t fields[], const void *src_struct)
{
    /* First calculate the message size using a non-writing substream. */
    pb_ostream_t substream = PB_OSTREAM_SIZING;
    size_t size;

    /* Use a substream to verify that a callback doesn't write more than
     * what it did the first time. */
    substream.callback = stream->callback;
    substream.state = (void *)((pb_byte_t*)(stream->state) + 1); // leave room for substream size
    substream.max_size = stream->max_size - 1;
    substream.bytes_written = 0;
#ifndef PB_NO_ERRMSG
    substream.errmsg = NULL;
#endif

    if (!pb_encode(&substream, fields, src_struct))
    {
#ifndef PB_NO_ERRMSG
        printf("pb_encode_submessage - pb_encode failed\n");
        stream->errmsg = substream.errmsg;
#endif
        return false;
    }

    size = substream.bytes_written;
    if(size > VARINT_ONE_BYTE)
    {
        if (!pb_shift_data_1_byte(stream, substream.bytes_written))
            return false;
        substream.state = (pb_byte_t*)substream.state + 1;
    }

    // We can't set stream->state to an updated value before we encode size, because it contains the
    // location of size. There is an implicit maximum size of 2^14 supported by this code, due to the
    // fact that the byte shift operation is only performed once. This is fine for ethernet, where
    // our (more restrictive) max size is closer to 2^10
    if (!pb_encode_varint(stream, (pb_uint64_t)size))
        return false;
    stream->bytes_written += substream.bytes_written;
    stream->state = substream.state;

#ifndef PB_NO_ERRMSG
    stream->errmsg = substream.errmsg;
#endif

    // if execution has reached here then everything is successful
    return true; 
}

/* Field encoders */

static bool checkreturn pb_enc_varint(pb_ostream_t *stream, const pb_field_t *field, const void *src)
{
    pb_int64_t value = 0;
    
    if (field->data_size == sizeof(int_least8_t))
        value = *(const int_least8_t*)src;
    else if (field->data_size == sizeof(int_least16_t))
        value = *(const int_least16_t*)src;
    else if (field->data_size == sizeof(int32_t))
        value = *(const int32_t*)src;
    else if (field->data_size == sizeof(pb_int64_t))
        value = *(const pb_int64_t*)src;
    else
        PB_RETURN_ERROR(stream, "invalid data_size");
    
#ifdef PB_WITHOUT_64BIT
    if (value < 0)
      return pb_encode_negative_varint(stream, (pb_uint64_t)value);
    else
#endif
      return pb_encode_varint(stream, (pb_uint64_t)value);
}

static bool checkreturn pb_enc_uvarint(pb_ostream_t *stream, const pb_field_t *field, const void *src)
{
    pb_uint64_t value = 0;
    
    if (field->data_size == sizeof(uint_least8_t))
        value = *(const uint_least8_t*)src;
    else if (field->data_size == sizeof(uint_least16_t))
        value = *(const uint_least16_t*)src;
    else if (field->data_size == sizeof(uint32_t))
        value = *(const uint32_t*)src;
    else if (field->data_size == sizeof(pb_uint64_t))
        value = *(const pb_uint64_t*)src;
    else
        PB_RETURN_ERROR(stream, "invalid data_size");
    
    return pb_encode_varint(stream, value);
}

static bool checkreturn pb_enc_svarint(pb_ostream_t *stream, const pb_field_t *field, const void *src)
{
    pb_int64_t value = 0;
    
    if (field->data_size == sizeof(int_least8_t))
        value = *(const int_least8_t*)src;
    else if (field->data_size == sizeof(int_least16_t))
        value = *(const int_least16_t*)src;
    else if (field->data_size == sizeof(int32_t))
        value = *(const int32_t*)src;
    else if (field->data_size == sizeof(pb_int64_t))
        value = *(const pb_int64_t*)src;
    else
        PB_RETURN_ERROR(stream, "invalid data_size");
    
    return pb_encode_svarint(stream, value);
}

static bool checkreturn pb_enc_fixed64(pb_ostream_t *stream, const pb_field_t *field, const void *src)
{
    PB_UNUSED(field);
#ifndef PB_WITHOUT_64BIT
    return pb_encode_fixed64(stream, src);
#else
    PB_UNUSED(src);
    PB_RETURN_ERROR(stream, "no 64bit support");
#endif
}

static bool checkreturn pb_enc_fixed32(pb_ostream_t *stream, const pb_field_t *field, const void *src)
{
    PB_UNUSED(field);
    return pb_encode_fixed32(stream, src);
}

static bool checkreturn pb_enc_bytes(pb_ostream_t *stream, const pb_field_t *field, const void *src)
{
    const pb_bytes_array_t *bytes = NULL;

    bytes = (const pb_bytes_array_t*)src;
    
    if (src == NULL)
    {
        /* Treat null pointer as an empty bytes field */
        return pb_encode_string(stream, NULL, 0);
    }
    
    if (PB_ATYPE(field->type) == PB_ATYPE_STATIC &&
        PB_BYTES_ARRAY_T_ALLOCSIZE(bytes->size) > field->data_size)
    {
        PB_RETURN_ERROR(stream, "bytes size exceeded");
    }
    
    return pb_encode_string(stream, bytes->bytes, bytes->size);
}

static bool checkreturn pb_enc_string(pb_ostream_t *stream, const pb_field_t *field, const void *src)
{
    size_t size = 0;
    size_t max_size = field->data_size;
    const char *p = (const char*)src;
    
    if (PB_ATYPE(field->type) == PB_ATYPE_POINTER)
        max_size = (size_t)-1;

    if (src == NULL)
    {
        size = 0; /* Treat null pointer as an empty string */
    }
    else
    {
        /* strnlen() is not always available, so just use a loop */
        while (size < max_size && *p != '\0')
        {
            size++;
            p++;
        }
    }

    return pb_encode_string(stream, (const pb_byte_t*)src, size);
}

static bool checkreturn pb_enc_submessage(pb_ostream_t *stream, const pb_field_t *field, const void *src)
{
    if (field->ptr == NULL)
        PB_RETURN_ERROR(stream, "invalid field descriptor");
    
    return pb_encode_submessage(stream, (const pb_field_t*)field->ptr, src);
}

static bool checkreturn pb_enc_fixed_length_bytes(pb_ostream_t *stream, const pb_field_t *field, const void *src)
{
    return pb_encode_string(stream, (const pb_byte_t*)src, field->data_size);
}
