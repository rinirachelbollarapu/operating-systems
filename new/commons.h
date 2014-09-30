
struct en_de_crypt_args
{
	int algo;
	int op;	
	long key;
};

struct de_compress_args
{
	int algo;
	int op;
	//char* test;
};

struct checksum_args
{
	int algo;
};

struct list_args
{
	int total;
	void* buffer;
};

struct rem_args
{
	int toberem;
};

struct my_job
{
	int jobID;
	int ret;
	char *filename;
	char *outfile;
	union
	{
		struct en_de_crypt_args edargs;
		struct de_compress_args compargs;
		struct checksum_args chsumargs;
		struct list_args ljobargs;
		struct rem_args rjobargs;
	};
};

struct currjob_list
{
	int jobID;
	char filename[256];	
};
