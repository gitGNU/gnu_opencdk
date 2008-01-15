/* new-io.h - new I/O interface
 *       Copyright (C) 2007 Timo Schulz
 *
 * This file is part of OpenCDK.
 *
 * OpenCDK is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * OpenCDK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef CDK_NEW_IO_H
#define CDK_NEW_IO_H 1

#include <gcrypt.h> /* for gcry_md_hd_t */

/* Opaque writer context. */
struct cdk_writer_s;
typedef struct cdk_writer_s *cdk_writer_t;

/* Opaque reader context. */
struct cdk_reader_s;
typedef struct cdk_reader_s *cdk_reader_t;

/* Writer specific callback functions. */
struct cdk_writer_cbs_s
{
  int (*write)(cdk_writer_t w, void *ctx, const void *buf, size_t buflen);
  int (*flush)(cdk_writer_t w);
  int (*release)(void *ctx); /* Release the private context. */
  int (*init)(void **r_ctx); /* Initialize the private context. */
};
typedef struct cdk_writer_cbs_s *cdk_writer_cbs_t;


/* Reader specific callback functions. */
struct cdk_reader_cbs_s
{
  int (*read)(cdk_reader_t r, void *ctx, void *buf, size_t buflen);
  int (*release)(void *ctx);
  int (*init)(void **r_ctx);
};
typedef struct cdk_reader_cbs_s *cdk_reader_cbs_t;


/* Reader interface. */

/* Create a custom reader with the given callback set and
   optionally a next writer object. */
cdk_error_t cdk_reader_new (cdk_reader_t *r_rd, cdk_reader_t next,
			    cdk_reader_cbs_t cbs, void *cbs_ctx);


/* Opaque file reader context. */
struct file_reader_s;
typedef struct file_reader_s *file_reader_t;

/* Allocate a new file reader. */
cdk_error_t file_reader_new (file_reader_t *r_rd, const char *filename);

/* Associate a file with the given file reader. */
cdk_error_t file_reader_set_filename (file_reader_t rd, const char *filename);

/* Allocate and open new file reader. */
cdk_error_t cdk_reader_file_new (cdk_reader_t *r_rd, file_reader_t file);


/* Generic functions to close or read from a reader. */
cdk_error_t cdk_reader_close (cdk_reader_t rd);
int cdk_reader_read (cdk_reader_t rd, void *buf, size_t buflen);

/* Helper to read a line from the given reader.
   The line will be returned without the line ending characters. */
int cdk_reader_readline (cdk_reader_t rd, void *buf, size_t buflen);


/* Opaque digest reader structure. */
struct digest_reader_s;
typedef struct digest_reader_s *digest_reader_t;

/* Reader to calculate a digest of a file. */
cdk_error_t digest_reader_new (digest_reader_t *r_md, int algo);

/* Set the message digest algorithm for this reader.
   This overrides the default algorithm. */
cdk_error_t digest_reader_set_algorithm (digest_reader_t md, int algorithm);

/* Return an allocated copy of the message digest handle.
   The caller must free the data. */
cdk_error_t digest_reader_get_handle (digest_reader_t md,
				      gcry_md_hd_t *r_md);

/* Allocate a new digest reader. */
cdk_error_t cdk_reader_digest_new (cdk_reader_t *r_rd, cdk_reader_t next,
				   digest_reader_t md);

/* Opaque buffer reader structure. */
struct buffer_reader_s;
typedef struct buffer_reader_s *buffer_reader_t;

cdk_error_t buffer_reader_new (buffer_reader_t *r_ctx,
			       const void *buf, size_t buflen);

cdk_error_t cdk_reader_buffer_new (cdk_reader_t *r_rd, buffer_reader_t buf);


/* Utility function. */
int _cdk_reader_read_next (cdk_reader_t rd, void *buf, size_t buflen);

/* Return the next reader object in the chain. */
cdk_reader_t cdk_reader_get_next (cdk_reader_t r);

/* Return the opaque context that is associated to this reader object. */
void *cdk_reader_get_opaque (cdk_reader_t r);

/* Writer interface. */

/* Allocate a new writer from a set of customized callbacks. */
cdk_error_t cdk_writer_new (cdk_writer_t *wr, cdk_writer_t next,
			    cdk_writer_cbs_t cbs, void *cbs_ctx);

/* Opaque file writer structure. */
struct file_writer_s;
typedef struct file_writer_s *file_writer_t;

/* Allocate a new file writer and open it. */
cdk_error_t cdk_writer_file_new (cdk_writer_t *wr, file_writer_t fp);

/* Allocate a new file writer. */
cdk_error_t file_writer_new (file_writer_t *r_fp, const char *file);

/* Set the file name for the file writer.
   This overwrites the file name given at the init procedure. */
cdk_error_t file_writer_set_filename (file_writer_t fp, const char *filename);

/* Generic functions to close or write to a writer. */
cdk_error_t cdk_writer_close (cdk_writer_t wr);
int cdk_writer_write (cdk_writer_t wr, const void *buf, size_t buflen);

/* Buffered writer .*/
struct buffered_writer_s;
typedef struct buffered_writer_s *buffered_writer_t;

/* Allocate a new buffered writer. */
cdk_error_t buffered_writer_new (buffered_writer_t *r_buf);

/* Set the buffer size of the buffered writer. */
cdk_error_t buffered_writer_set_bufsize (buffered_writer_t buf, size_t bufsize);

/* Allocate and open a new buffered writer. */
cdk_error_t cdk_writer_buffered_new (cdk_writer_t *wr, cdk_writer_t next,
				     buffered_writer_t buf);

/* Compression writer. */

/* Compress writer. */
struct compress_writer_s;
typedef struct compress_writer_s *compress_writer_t;

/* Allocate a new compression writer. */
cdk_error_t compress_writer_new (compress_writer_t *zip, int algo);

/* Set the compression algorithm for this reader.
   This overrides the default algorithm. */
cdk_error_t compress_writer_set_algorithm (compress_writer_t zip,
					   int algo);

/* Allocate and open a new compression writer. */
cdk_error_t cdk_writer_compress_new (cdk_writer_t *r_wr, cdk_writer_t next,
				     compress_writer_t zip);

/* ASCII armor writer. */
struct armor_writer_s;
typedef struct armor_writer_s *armor_writer_t;

/* Allocate a new armor writer structure. */
cdk_error_t armor_writer_new (armor_writer_t *r_arm, int msgtype);

/* Set the message type of the armor.
   This overrides the default value. */
cdk_error_t armor_writer_set_msg_type (armor_writer_t arm, int msg_type);

/* Allocate a new armor writer and open it. */
cdk_error_t cdk_writer_armor_new (cdk_writer_t *r_wr, cdk_writer_t next,
				  armor_writer_t arm);


/* Cipher writer context. */
struct cipher_writer_s;
typedef struct cipher_writer_s *cipher_writer_t;

/* Allocate a new cipher writer. */
cdk_error_t cipher_writer_new (cipher_writer_t *r_enc, size_t bufsize);

/* Associate a DEK object with the given writer. */
cdk_error_t cipher_writer_set_dek (cipher_writer_t enc, cdk_dek_t dek);

/* Allocate and open a new cipher writer. */
cdk_error_t cdk_writer_cipher_new (cdk_writer_t *r_wr, cdk_writer_t next,
				   cipher_writer_t enc);

/* Buffer writer context. */
struct buffer_writer_s;
typedef struct buffer_writer_s *buffer_writer_t;

/* Allocate a new buffer writer. */
cdk_error_t buffer_writer_new (buffer_writer_t *r_buf);

/* Return the raw data which were written to the buffer. */
cdk_error_t buffer_writer_get_data (buffer_writer_t buf,
				    unsigned char **r_data, size_t *r_data_len);

/* Allocate and open a new buffer writer. */
cdk_error_t cdk_writer_buffer_new (cdk_writer_t *r_wr, buffer_writer_t buf);

/* Utility functions. */

int _cdk_writer_write_next (cdk_writer_t wr, const void *buf, size_t buflen);

/* Return the next writer in the chain. */
cdk_writer_t cdk_writer_get_next (cdk_writer_t wr);

/* Return the callback function set for the given writer. */
cdk_writer_cbs_t cdk_writer_get_cbs (cdk_writer_t w, void **r_ctx);

/* Attach another 'filter' callback set to the root writer.
   This allows the chaining of several callback sets.
   If no @cbs_ctx is given, default settings will be used. */
cdk_error_t cdk_writer_attach (cdk_writer_t root, 
			       cdk_writer_cbs_t cbs, void *cbs_ctx);

/* Return the associate internal context as an opaque handle.
   The value should be treated as opaque and only used in 
   customized callbacks to pass the handle to the next writer. */
void* cdk_writer_get_opaque (cdk_writer_t wr);


/* External callback set references to well known modules. */

/* Callback structure for the compress writer. */
extern struct cdk_writer_cbs_s compress_writer;

/* Callback structure for the armor writer. */
extern struct cdk_writer_cbs_s armor_writer;

/* Callback structure for the buffered writer. */
extern struct cdk_writer_cbs_s buffered_writer;

/* Callback structure for the file writer. */
extern struct cdk_writer_cbs_s file_writer;

/* Callback structure for the buffer writer. */
extern struct cdk_writer_cbs_s buffer_writer;

/* Callback structure for the digest reader. */
extern struct cdk_reader_cbs_s digest_reader;

/* Callback structure for the file reader. */
extern struct cdk_reader_cbs_s file_reader;

/* Callback structure for the cipher writer. */
extern struct cdk_writer_cbs_s cipher_writer;

/* Callback structure for the buffer reader. */
extern struct cdk_reader_cbs_s buffer_reader;

#endif /*CDK_NEW_IO_H*/
