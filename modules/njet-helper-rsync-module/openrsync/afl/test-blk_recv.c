#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "../md4.h"
#include "../extern.h"

int
main(int argc, char *argv[])
{
	int	 	 fd;
	struct opts	 opts;
	size_t		 sz;
	struct blkset	*p;

	memset(&opts, 0, sizeof(struct opts));

	assert(2 == argc);

	fd = open(argv[1], O_NONBLOCK | O_RDONLY, 0);
	assert(fd != -1);

	p = blk_recv(&opts, fd, 16, "");
	blkset_free(p);
	return EXIT_SUCCESS;
}
