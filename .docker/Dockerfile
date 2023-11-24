FROM nginx:latest

ARG PSXploit-host

COPY .docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY . /usr/share/nginx/html/
RUN rm -R /usr/share/nginx/html/.docker

WORKDIR /usr/local/bin/
RUN touch /var/run/nginx.pid \
 && chown -R nginx:nginx /var/run/nginx.pid /var/cache/nginx

RUN chown -R nginx:nginx /var/cache/nginx && \
        chown -R nginx:nginx /var/log/nginx && \
        chown -R nginx:nginx /etc/nginx/conf.d

USER nginx

EXPOSE 80
EXPOSE 443
