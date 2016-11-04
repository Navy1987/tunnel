#ifndef __socket5_zproto_h
#define __socket5_zproto_h
#include "zprotowire.h"
namespace socket5_zproto {

using namespace zprotobuf;

struct connect:public wire {
        uint32_t type;
        std::string addr;
        uint32_t port;
protected:
        virtual int _encode_field(struct zproto_args *args) const;
        virtual int _decode_field(struct zproto_args *args);
public:
        virtual const char *_name() const;
};
struct data:public wire {
        std::string data;
protected:
        virtual int _encode_field(struct zproto_args *args) const;
        virtual int _decode_field(struct zproto_args *args);
public:
        virtual const char *_name() const;
};
class serializer:public wiretree {
public:
	 serializer();
	 static serializer &instance();
};

}
#endif
