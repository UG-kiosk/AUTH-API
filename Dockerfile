FROM node:20-alpine as builder
COPY . . 
RUN yarn install
RUN yarn build

FROM node:20-alpine
WORKDIR /app
COPY --from=builder package.json yarn.lock /app/
RUN yarn install --production=true
COPY --from=builder dist/ /app/dist/

EXPOSE 3000
ENTRYPOINT [ "yarn", "start" ]