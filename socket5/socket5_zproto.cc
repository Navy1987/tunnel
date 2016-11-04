#include <string.h>
#include "zprotowire.h"
#include "socket5_zproto.hpp"
namespace socket5_zproto {

using namespace zprotobuf;

const char *
connect::_name() const
{
	return "connect";
}
int
connect::_encode_field(struct zproto_args *args) const
{
	switch (args->tag) {
	 case 1:
		 if (args->buffsz < sizeof(uint32_t))
			 return ZPROTO_OOM;
		 (*(uint32_t *)args->buff) = type;
		 return sizeof(uint32_t);
	 case 2:
		 if (args->buffsz < addr.size())
			 return ZPROTO_OOM;
		 memcpy(args->buff, addr.c_str(), addr.size());
		 return addr.size();
	 case 3:
		 if (args->buffsz < sizeof(uint32_t))
			 return ZPROTO_OOM;
		 (*(uint32_t *)args->buff) = port;
		 return sizeof(uint32_t);
	 default:
		 return ZPROTO_ERROR;
	 }
}
int
connect::_decode_field(struct zproto_args *args) 
{
	switch (args->tag) {
	 case 1:
		 type = (*(uint32_t *)args->buff);
		 return sizeof(uint32_t);
	 case 2:
		 addr.assign((char *)args->buff, args->buffsz);
		 return args->buffsz;
	 case 3:
		 port = (*(uint32_t *)args->buff);
		 return sizeof(uint32_t);
	 default:
		 return ZPROTO_ERROR;
	 }
}
const char *
data::_name() const
{
	return "data";
}
int
data::_encode_field(struct zproto_args *args) const
{
	switch (args->tag) {
	 case 1:
		 if (args->buffsz < data.size())
			 return ZPROTO_OOM;
		 memcpy(args->buff, data.c_str(), data.size());
		 return data.size();
	 default:
		 return ZPROTO_ERROR;
	 }
}
int
data::_decode_field(struct zproto_args *args) 
{
	switch (args->tag) {
	 case 1:
		 data.assign((char *)args->buff, args->buffsz);
		 return args->buffsz;
	 default:
		 return ZPROTO_ERROR;
	 }
}
const char *def = "\x63\x6f\x6e\x6e\x65\x63\x74\x20\x30\x78\x30\x31\x20\x7b\xa\x9\x23\x31\x20\x2d\x2d\x3e\x20\x69\x70\x2c\x20\x23\x32\x20\x2d\x2d\x3e\x20\x64\x6f\x6d\x61\x69\x6e\xa\x9\x2e\x74\x79\x70\x65\x3a\x69\x6e\x74\x65\x67\x65\x72\x20\x31\xa\x9\x2e\x61\x64\x64\x72\x3a\x73\x74\x72\x69\x6e\x67\x20\x32\xa\x9\x2e\x70\x6f\x72\x74\x3a\x69\x6e\x74\x65\x67\x65\x72\x20\x33\xa\x7d\xa\xa\x64\x61\x74\x61\x20\x30\x78\x30\x32\x20\x7b\xa\x9\x2e\x64\x61\x74\x61\x3a\x73\x74\x72\x69\x6e\x67\x20\x31\xa\x7d\xa\xa";

serializer::serializer()
	 :wiretree(def)
{}
serializer &
serializer::instance()
{
	 static serializer *inst = new serializer();
	 return *inst;
}

}
