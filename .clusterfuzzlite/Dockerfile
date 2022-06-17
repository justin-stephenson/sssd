FROM gcr.io/oss-fuzz-base/base-builder:v1
COPY . $SRC/sssd
RUN apt-get update && apt-get -y install sudo dialog apt-utils rpm
WORKDIR sssd
COPY .clusterfuzzlite/build.sh $SRC/
