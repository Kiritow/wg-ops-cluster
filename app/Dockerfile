FROM ubuntu:latest
RUN apt update && apt install -y xz-utils
COPY node-v16.15.0-linux-x64.tar.xz /tmp/
RUN cd /tmp && mkdir node && tar -xJvf node-v16.15.0-linux-x64.tar.xz --strip-components=1 -C /tmp/node

FROM ubuntu:latest
COPY --from=0 /tmp/node/ /usr/local/
RUN apt update && apt install -y openssl
COPY package.json /root/
COPY package-lock.json /root/
RUN cd /root && /usr/local/bin/npm install 
COPY . /root/
WORKDIR /root/
ENTRYPOINT ["/usr/local/bin/node", "app.js"]
EXPOSE 3000
