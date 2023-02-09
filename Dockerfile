FROM node:lts-buster
WORKDIR /usr/src/app
COPY . .
RUN npm install
RUN npm rebuild node-sass
RUN npm run build:styles
RUN npm run build:webauthn
EXPOSE 8080
CMD ["npm", "start"]