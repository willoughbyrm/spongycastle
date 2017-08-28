#!/bin/bash 

# Package rename org.bouncycastle to org.spongycastle
    
# find -name bouncycastle | xargs rename s/bouncycastle/spongycastle/

# find {core,jce,kmip,misc,pg,pkix,prov,tls,test} -type f | xargs -I '{}' ssed -i -R 's/bouncycastle(?!.org)/spongycastle/g' '{}'

# BC to SC for provider name
    
find {core,jce,kmip,misc,pg,pkix,prov,tls,test} -type f | xargs -I '{}' ssed -i -R s/'"'BC(|JSSE)?'"'/'"'SC$1'"'/g '{}'


