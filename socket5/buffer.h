#ifndef	_BUFFER_H
#define	_BUFFER_H

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <memory.h>

class buffer {
public:
	uint8_t *data;
	size_t  datasz;
	size_t  datacap;
public:
	buffer();
	~buffer();
private:
	int tryread(int s, void *buff, size_t sz);
	void inline check(size_t need)
	{
		if (this->datasz + need <= this->datacap)
			return ;
		this->datacap = this->datasz + need;
		this->data = (uint8_t *)realloc(this->data, this->datacap);
		return ;
	}
public:
	void inline out(size_t n)
	{
		size_t delta = 0;
		assert(n <= this->datasz);
		if (this->datasz > n) {
			delta = this->datasz - n;
			memmove(this->data, &this->data[n], delta);
		}
		this->datasz = delta;
		return ;
	}

	void inline in(const void *data, size_t n)
	{
		check(n);
		memcpy(&this->data[this->datasz], data, n);
		this->datasz += n;
		return ;
	}

	int inline read(int fd)
	{
		int err;
		if (this->datasz == this->datacap)
			check(64 * 1024);
		err = tryread(fd, &this->data[this->datasz], this->datacap - this->datasz);
		if (err < 0)
			return -1;
		this->datasz += err;
		return err;
	}

	int inline write(int fd)
	{
		int err;
		if (this->datasz == 0)
			return 0;
		err = ::write(fd, this->data, this->datasz);
		if (err <= 0)
			return err;
		assert(err >= 1);
		out(err);
		return err;
	}
};



#endif

