curl -LO https://opensource.apple.com/tarballs/cctools/cctools-927.0.2.tar.gz
mkdir cctools-tmp
tar -xzf cctools-927.0.2.tar.gz -C cctools-tmp/
sed -i "s_#include_//_g" cctools-tmp/*cctools-927.0.2/include/mach-o/loader.h
sed -i -e "s=<stdint.h>=\n#include <stdint.h>\ntypedef int integer_t;\ntypedef integer_t cpu_type_t;\ntypedef integer_t cpu_subtype_t;\ntypedef integer_t cpu_threadtype_t;\ntypedef int vm_prot_t;=g" cctools-tmp/*cctools-927.0.2/include/mach-o/loader.h
cp -r cctools-tmp/*cctools-927.0.2/include/* /usr/local/include/
